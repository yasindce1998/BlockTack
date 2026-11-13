//! In-memory multi-transaction simulation with revm: executes raw
//! transaction sequences against fork state fetched over RPC, without
//! broadcasting anything — not even to the local chain.

use crate::finding::Finding;
use alloy::consensus::transaction::SignerRecoverable;
use alloy::consensus::{Transaction, TxEnvelope};
use alloy::eips::BlockId;
use alloy::primitives::{Address, Bytes, TxKind, U256};
use alloy::providers::{DynProvider, Provider};
use alloy::rlp::Decodable;
use revm::context::result::{ExecutionResult, Output};
use revm::context::{BlockEnv, TxEnv};
use revm::database::AlloyDB;
use revm::database_interface::async_db::DatabaseAsyncRef;
use revm::database_interface::{DatabaseAsync, WrapDatabaseAsync};
use revm::handler::{ExecuteEvm, MainBuilder, MainContext, MainnetEvm, MainnetContext};
use revm::state::{AccountInfo, Bytecode};
use revm::Context;

/// A balance report requested after the simulated sequence.
#[derive(Clone)]
pub struct Report {
    pub token: Option<Address>,
    pub account: Address,
    pub min_profit: Option<U256>,
}

/// simulate-tx-sequence: execute a sequence of raw (signed) transactions
/// entirely in memory against fork state, then report balances. This is
/// the "would the whole attack work" primitive — no transaction is ever
/// broadcast, not even to a local chain.
///
/// options:
///   rawFiles: paths to raw transaction files (repo-relative), executed
///             in order
///   reports:  [{token?: address, account: address, minProfit?: decimal}]
///
/// The revm work runs on a dedicated thread with its own multi-thread
/// runtime: WrapDatabaseAsync's sync Database impl block_on's through a
/// runtime handle, which cannot happen inside an async context.
pub fn simulate_tx_sequence(
    rpc_url: &str,
    raw_files: &[String],
    reports: &[Report],
) -> anyhow::Result<Vec<Finding>> {
    let url = rpc_url.to_string();
    let files: Vec<String> = raw_files.to_vec();
    let report_list: Vec<Report> = reports.to_vec();

    let handle = std::thread::spawn(move || -> anyhow::Result<Vec<Finding>> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let _guard = rt.enter();

        // Block context from the fork's head, and the fork state DB —
        // both built inside this thread's runtime.
        let (provider, header) = rt.block_on(async {
            let provider = crate::actions::connect(&url).await?;
            let block = provider
                .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
                .await?
                .ok_or_else(|| anyhow::anyhow!("latest block not found"))?;
            anyhow::Ok((provider, block.header))
        })?;

        let mut block_env = BlockEnv::default();
        block_env.number = U256::from(header.number);
        block_env.timestamp = U256::from(header.timestamp);
        block_env.gas_limit = 30_000_000;
        block_env.basefee = header.base_fee_per_gas.unwrap_or(0);

        let db = WrapDatabaseAsync::new(AlloyDbAsync(AlloyDB::new(
            provider,
            BlockId::number(header.number),
        )))
        .ok_or_else(|| anyhow::anyhow!("no async runtime handle available for the state DB"))?;

        let mut ctx = Context::mainnet().with_db(db);
        ctx.block = block_env;
        // Simulation semantics for the synthetic report calls: no
        // balance/base-fee/nonce gating on the internal balanceOf probes.
        ctx.cfg.disable_balance_check = true;
        ctx.cfg.disable_base_fee = true;
        ctx.cfg.disable_nonce_check = true;
        let mut evm = ctx.build_mainnet();

        let mut findings = Vec::new();

        // 1. Execute the sequence; state carries across transactions in
        //    the journal until finalize.
        for (i, path) in files.iter().enumerate() {
            let raw = std::fs::read_to_string(path)?
                .trim()
                .trim_start_matches("0x")
                .to_string();
            let bytes = alloy::hex::decode(&raw)
                .map_err(|e| anyhow::anyhow!("decode raw tx {path}: {e}"))?;
            let tx = TxEnvelope::decode(&mut bytes.as_slice())
                .map_err(|e| anyhow::anyhow!("rlp-decode raw tx {path}: {e}"))?;
            let signer = tx
                .recover_signer()
                .map_err(|e| anyhow::anyhow!("recover signer for {path}: {e}"))?;

            let env = tx_env_from_envelope(&tx, signer);
            let tx_type = u8::from(tx.tx_type()) as u64;
            match evm.transact_one(env) {
                Ok(result) if result.is_success() => findings.push(
                    Finding::new(
                        "engine-evm-simulate-seq-tx",
                        format!("Transaction {} executed in simulation", i + 1),
                        "info",
                    )
                    .with("confidence", "confirmed")
                    .with("layer", "L2")
                    .with(
                        "evidence",
                        format!(
                            "file={path} type={tx_type} from={signer} gas_used={} — state \
                             applied in memory, nothing broadcast",
                            result.tx_gas_used()
                        ),
                    ),
                ),
                Ok(result) => findings.push(
                    Finding::new(
                        "engine-evm-simulate-seq-revert",
                        format!("Transaction {} reverted in simulation", i + 1),
                        "medium",
                    )
                    .with("confidence", "confirmed")
                    .with("layer", "L2")
                    .with(
                        "evidence",
                        format!(
                            "file={path} type={tx_type} from={signer} gas_used={} result={result:?}",
                            result.tx_gas_used(),
                        ),
                    ),
                ),
                Err(e) => findings.push(
                    Finding::new(
                        "engine-evm-simulate-seq-error",
                        format!("Transaction {} failed to execute in simulation", i + 1),
                        "medium",
                    )
                    .with("layer", "L2")
                    .with("evidence", format!("file={path} error={e}")),
                ),
            }
        }

        // 2. Token balance reports, executed as zero-value calls in the
        //    same post-sequence state.
        for report in &report_list {
            if let Some(token) = report.token {
                if let Some(balance) = call_balance_of(&mut evm, token, report.account) {
                    let is_profit = report.min_profit.map_or(false, |min| balance >= min);
                    let (id, title, severity) = if is_profit {
                        (
                            "engine-evm-simulate-seq-profit",
                            format!("Simulated token profit verified: {}", report.account),
                            "critical",
                        )
                    } else {
                        (
                            "engine-evm-simulate-seq-balance",
                            format!("Simulated ERC-20 balance: {}", report.account),
                            "info",
                        )
                    };
                    findings.push(
                        Finding::new(id, title, severity)
                            .with("confidence", "confirmed")
                            .with("layer", "L5")
                            .with("target", report.account.to_string())
                            .with(
                                "description",
                                if is_profit {
                                    "The post-sequence balance reached the declared profit \
                                     threshold in pure simulation — the attack works without a \
                                     single broadcast, not even to a local chain."
                                        .to_string()
                                } else {
                                    String::new()
                                },
                            )
                            .with(
                                "evidence",
                                format!(
                                    "token={token} account={} balance={balance} (simulated)",
                                    report.account
                                ),
                            ),
                    );
                }
            }
        }

        // 3. Native balance reports, from the finalized state map.
        let state = evm.finalize();
        for report in &report_list {
            if report.token.is_none() {
                if let Some(account) = state.get(&report.account) {
                    findings.push(
                        Finding::new(
                            "engine-evm-simulate-seq-balance",
                            format!("Simulated native balance: {}", report.account),
                            "info",
                        )
                        .with("confidence", "confirmed")
                        .with("layer", "L5")
                        .with("target", report.account.to_string())
                        .with(
                            "evidence",
                            format!(
                                "account={} balance={} (simulated, post-sequence state)",
                                report.account, account.info.balance
                            ),
                        ),
                    );
                }
            }
        }

        Ok(findings)
    });

    handle
        .join()
        .map_err(|_| anyhow::anyhow!("simulation worker thread panicked"))?
}

/// Convert a signed envelope into revm's transaction environment.
fn tx_env_from_envelope(tx: &TxEnvelope, signer: Address) -> TxEnv {
    let mut env = TxEnv::default();
    env.tx_type = u8::from(tx.tx_type());
    env.caller = signer;
    env.gas_limit = tx.gas_limit();
    // Effective gas price: for EIP-1559+ txs use max_fee_per_gas (the
    // historical fees exceed typical fork base fees, so execution is
    // unaffected in practice).
    env.gas_price = tx.max_fee_per_gas() as u128;
    env.kind = match tx.to() {
        Some(to) => TxKind::Call(to),
        None => TxKind::Create,
    };
    env.value = tx.value();
    env.data = Bytes::copy_from_slice(tx.input());
    env.nonce = tx.nonce();
    env.chain_id = tx.chain_id();
    env
}

/// Adapter: AlloyDB implements `DatabaseAsyncRef` (&self), while
/// `WrapDatabaseAsync` needs `DatabaseAsync` (&mut self). This shim
/// delegates the mutable methods to the ref methods.
struct AlloyDbAsync(AlloyDB<alloy::network::Ethereum, DynProvider>);

impl DatabaseAsync for AlloyDbAsync {
    type Error = revm::database::AlloyDBError;

    async fn basic_async(
        &mut self,
        address: Address,
    ) -> Result<Option<AccountInfo>, Self::Error> {
        self.0.basic_async_ref(address).await
    }

    async fn code_by_hash_async(
        &mut self,
        code_hash: alloy::primitives::B256,
    ) -> Result<Bytecode, Self::Error> {
        self.0.code_by_hash_async_ref(code_hash).await
    }

    async fn storage_async(
        &mut self,
        address: Address,
        index: U256,
    ) -> Result<U256, Self::Error> {
        self.0.storage_async_ref(address, index).await
    }

    async fn block_hash_async(&mut self, number: u64) -> Result<alloy::primitives::B256, Self::Error> {
        self.0.block_hash_async_ref(number).await
    }
}

/// Concrete simulation EVM type: mainnet EVM over an async-wrapped
/// AlloyDB fork-state database.
type SimDb = WrapDatabaseAsync<AlloyDbAsync>;
type SimEvm = MainnetEvm<MainnetContext<SimDb>>;

/// Execute a balanceOf call in the current simulated state.
fn call_balance_of(evm: &mut SimEvm, token: Address, account: Address) -> Option<U256> {
    let mut env = TxEnv::default();
    env.caller = Address::ZERO;
    env.gas_limit = 1_000_000;
    env.gas_price = 0;
    env.kind = TxKind::Call(token);
    env.data = {
        let calldata = crate::actions::encode_calldata("balanceOf(address)", &[]).ok()?;
        let mut call = calldata;
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(account.as_slice());
        call.extend_from_slice(&word);
        Bytes::from(call)
    };
    let result: ExecutionResult<_> = evm.transact_one(env).ok()?;
    let bytes = result.output()?;
    if bytes.len() < 32 {
        return None;
    }
    Some(U256::from_be_bytes::<32>(bytes[..32].try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_vendored_curve_tx_and_recovers_attacker() {
        // The first vendored Curve/Vyper transaction must decode as a
        // signed envelope and recover the known attacker EOA.
        let raw = std::fs::read_to_string(
            "../corpus/curve-vyper-2023/transactions/01_0xa84aa065ce61dbb1eb50ab6ae67fc31a9da50dd2c74eefd561661bfce2f1620c.raw",
        )
        .expect("vendored curve tx");
        let raw = raw.trim().trim_start_matches("0x");
        let bytes = alloy::hex::decode(raw).expect("hex");
        let tx = TxEnvelope::decode(&mut bytes.as_slice()).expect("rlp decode");
        let signer = tx.recover_signer().expect("signer");
        assert_eq!(
            signer,
            "0x6Ec21d1868743a44318c3C259a6d4953F9978538"
                .parse::<Address>()
                .unwrap()
        );
        // The exploit targets the attack contract.
        assert_eq!(
            tx.to().unwrap(),
            "0x9420F8821aB4609Ad9FA514f8D2F5344C3c0A6Ab"
                .parse::<Address>()
                .unwrap()
        );
    }
}
