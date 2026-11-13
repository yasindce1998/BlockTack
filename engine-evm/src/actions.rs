//! Engine actions: the real chain-facing capabilities of BlockTack.

use crate::finding::Finding;
use alloy::eips::BlockId;
use alloy::network::TransactionBuilder;
use alloy::primitives::map::B256HashMap;
use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::eth::state::{AccountOverride, StateOverride};
use alloy::rpc::types::TransactionRequest;

/// Connect to an RPC endpoint and return a type-erased provider.
pub async fn connect(rpc_url: &str) -> anyhow::Result<DynProvider> {
    let provider = ProviderBuilder::new().connect(rpc_url).await?;
    Ok(DynProvider::new(provider))
}

/// Connect with a default historical block applied to block-parameterized
/// calls (eth_getBalance, eth_getCode, ...).
pub async fn connect_at_block(
    rpc_url: &str,
    block: alloy::eips::BlockId,
) -> anyhow::Result<DynProvider> {
    let provider = ProviderBuilder::new()
        .with_default_block(block)
        .connect(rpc_url)
        .await?;
    Ok(DynProvider::new(provider))
}

/// fingerprint: identify the chain — chain ID, head block, client version.
pub async fn fingerprint(provider: DynProvider) -> anyhow::Result<Vec<Finding>> {
    let chain_id = provider.get_chain_id().await?;
    let block_number = provider.get_block_number().await?;
    let client_version: String = provider
        .client()
        .request_noparams("web3_clientVersion")
        .await
        .unwrap_or_else(|e| format!("unavailable: {e}"));

    Ok(vec![
        Finding::new(
            "engine-evm-fingerprint",
            "Chain fingerprinted",
            "info",
        )
        .with("confidence", "confirmed")
        .with("layer", "L1")
        .with("weakness", "BTV-L1-001")
        .with(
            "description",
            "Chain identity established via JSON-RPC. Cross-reference the client version \
             with known client CVEs before attacking protocol handlers.",
        )
        .with(
            "evidence",
            format!(
                "chainId={chain_id} blockNumber={block_number} clientVersion={client_version}"
            ),
        ),
    ])
}

/// Oracle-related function signatures whose selectors we scan bytecode for.
/// A contract referencing these is either calling or implementing an
/// oracle read — both are leads for BTV-L2-003.
const ORACLE_SIGNATURES: &[(&str, &str)] = &[
    ("latestAnswer()", "Chainlink-style aggregator (legacy)"),
    ("latestRoundData()", "Chainlink-style aggregator (round data)"),
    (
        "getRoundData(uint80)",
        "Chainlink-style aggregator (historical rounds)",
    ),
    ("getReserves()", "AMM reserve read — Uniswap V2-style spot price"),
    (
        "price0CumulativeLast()",
        "Uniswap V2 cumulative price accumulator",
    ),
    (
        "price1CumulativeLast()",
        "Uniswap V2 cumulative price accumulator",
    ),
    ("slot0()", "Uniswap V3 slot0 spot price"),
    ("consult(address,uint256)", "Uniswap V2 oracle library consult"),
    ("peek()", "Maker-style oracle peek"),
    ("read()", "Maker-style oracle read"),
];

/// keccak256(signature)[0..4] — the EVM function selector.
fn selector(signature: &str) -> [u8; 4] {
    let hash = keccak256(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

/// Scan runtime bytecode for known oracle selectors.
fn scan_code(code: &[u8]) -> Vec<(&'static str, &'static str)> {
    ORACLE_SIGNATURES
        .iter()
        .filter(|(sig, _)| code.windows(4).any(|window| window == selector(sig).as_slice()))
        .map(|(sig, description)| (*sig, *description))
        .collect()
}

/// map-oracles: fetch deployed bytecode for each address and flag
/// oracle-related selectors. `addresses` come from the job options or,
/// failing that, from the target's contract list.
pub async fn map_oracles(
    provider: DynProvider,
    addresses: &[String],
) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for raw in addresses {
        let Ok(address) = raw.parse::<Address>() else {
            findings.push(
                Finding::new("engine-evm-map-oracles", "Invalid address skipped", "low")
                    .with("layer", "L2")
                    .with("description", format!("could not parse address: {raw}")),
            );
            continue;
        };

        let code = provider.get_code_at(address).await?;
        if code.is_empty() {
            findings.push(
                Finding::new(
                    "engine-evm-map-oracles-missing",
                    "Expected contract is not deployed",
                    "medium",
                )
                .with("layer", "L2")
                .with(
                    "description",
                    "eth_getCode returned empty bytecode for a contract listed in the target. \
                     Verify the address and chain.",
                )
                .with("evidence", format!("address={address} code=0x")),
            );
            continue;
        }

        let hits = scan_code(&code);
        if hits.is_empty() {
            findings.push(
                Finding::new(
                    "engine-evm-map-oracles-none",
                    "No known oracle selectors in bytecode",
                    "info",
                )
                .with("layer", "L2")
                .with(
                    "description",
                    "No oracle-related function selectors found; extend ORACLE_SIGNATURES \
                     if the target uses a non-standard feed.",
                )
                .with("evidence", format!("address={address} code_size={}", code.len())),
            );
        } else {
            for (signature, description) in hits {
                let sel = selector(signature);
                findings.push(
                    Finding::new(
                        "engine-evm-map-oracles",
                        format!("Oracle dependency: {signature}"),
                        "medium",
                    )
                    .with("confidence", "high")
                    .with("layer", "L2")
                    .with("weakness", "BTV-L2-003")
                    .with(
                        "description",
                        format!(
                            "Bytecode references {signature} ({description}). The contract calls \
                             or implements an oracle read — verify the feed is manipulation-\
                             resistant (spot pool? staleness? single operator?).",
                        ),
                    )
                    .with(
                        "evidence",
                        format!(
                            "address={address} selector=0x{:02x}{:02x}{:02x}{:02x} code_size={}",
                            sel[0], sel[1], sel[2], sel[3],
                            code.len()
                        ),
                    ),
                );
            }
        }
    }
    Ok(findings)
}

/// verify-pnl: compare an address's balance now versus N blocks ago and
/// report profit — the verification step of an economic exploit.
pub async fn verify_pnl(
    rpc_url: &str,
    attacker: &str,
    blocks_ago: u64,
) -> anyhow::Result<Vec<Finding>> {
    let address: Address = attacker
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid attacker address {attacker}: {e}"))?;

    let provider = connect(rpc_url).await?;
    let latest = provider.get_block_number().await?;
    let balance_now: U256 = provider.get_balance(address).await?;

    let past_block = latest.saturating_sub(blocks_ago);
    let provider_past = connect_at_block(rpc_url, BlockId::number(past_block)).await?;
    let balance_past: U256 = provider_past.get_balance(address).await?;

    let evidence = format!(
        "attacker={address} balance@{past_block}={}wei balance@{latest}={}wei",
        balance_past, balance_now
    );

    if balance_now > balance_past {
        Ok(vec![
            Finding::new("engine-evm-verify-pnl", "Exploit profit verified", "critical")
                .with("confidence", "confirmed")
                .with("layer", "L5")
                .with(
                    "description",
                    "The tracked address gained balance over the exploit window; the campaign's \
                     economic objective was achieved on this chain.",
                )
                .with("evidence", evidence),
        ])
    } else {
        Ok(vec![
            Finding::new("engine-evm-verify-pnl", "No profit detected", "info")
                .with("confidence", "confirmed")
                .with("layer", "L5")
                .with(
                    "description",
                    "The tracked address did not gain balance over the window (net of gas).",
                )
                .with("evidence", evidence),
        ])
    }
}

/// encode_calldata builds `selector || 32-byte big-endian words` for
/// function signatures with uint256 arguments only (the common case for
/// exploit parameters like borrow amounts).
fn encode_calldata(signature: &str, uint_args: &[U256]) -> anyhow::Result<Vec<u8>> {
    let sel = selector(signature);
    let mut calldata = Vec::with_capacity(4 + 32 * uint_args.len());
    calldata.extend_from_slice(&sel);
    for arg in uint_args {
        let word: [u8; 32] = arg.to_be_bytes();
        calldata.extend_from_slice(&word);
    }
    Ok(calldata)
}

/// Parse a U256 from a decimal or 0x-hex string.
pub fn parse_u256(raw: &str) -> anyhow::Result<U256> {
    let raw = raw.trim();
    if let Some(hex) = raw.strip_prefix("0x") {
        Ok(U256::from_str_radix(hex, 16)?)
    } else {
        Ok(U256::from_str_radix(raw, 10)?)
    }
}

/// simulate-call: execute a call against current chain state with storage
/// overrides — "what would happen if this storage slot held X" — without
/// broadcasting a transaction. This is how BlockTack verifies exploits
/// that must never touch even a local chain.
///
/// options:
///   to:        target contract address
///   function:  signature, e.g. "borrow(uint256)" (uint256 args only)
///   args:      list of uint256 args (decimal or 0x-hex strings)
///   from:      optional sender address
///   state:     {address: {slot: value}} storage overrides (decimal or
///              0x-hex slots/values)
pub async fn simulate_call(
    rpc_url: &str,
    options: &serde_json::Value,
) -> anyhow::Result<Vec<Finding>> {
    let to: Address = options
        .get("to")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("simulate-call requires options.to"))?
        .parse()?;
    let signature = options
        .get("function")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("simulate-call requires options.function"))?;
    let uint_args: Vec<U256> = options
        .get("args")
        .and_then(serde_json::Value::as_array)
        .map(|args| {
            args.iter()
                .filter_map(|a| a.as_str())
                .map(parse_u256)
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();

    let calldata = encode_calldata(signature, &uint_args)?;

    let mut tx = TransactionRequest::default();
    tx.set_to(to);
    tx.set_input(alloy::primitives::Bytes::from(calldata.clone()));
    if let Some(from) = options.get("from").and_then(serde_json::Value::as_str) {
        tx.set_from(from.parse()?);
    }
    if let Some(value) = options
        .get("value")
        .and_then(serde_json::Value::as_str)
        .map(parse_u256)
        .transpose()?
    {
        tx.set_value(value);
    }

    // Storage overrides: {address: {slot: value}}.
    let mut state_override = StateOverride::default();
    if let Some(map) = options.get("state").and_then(serde_json::Value::as_object) {
        for (addr_raw, slots) in map {
            let addr: Address = addr_raw.parse()?;
            let mut account = AccountOverride::default();
            let mut state: B256HashMap<B256> = Default::default();
            for (slot_raw, value_raw) in slots
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("state slots must be an object"))?
            {
                let slot = B256::new(U256::from(parse_u256(slot_raw)?).to_be_bytes());
                let value =
                    B256::new(U256::from(parse_u256(value_raw.as_str().unwrap_or_default())?).to_be_bytes());
                state.insert(slot, value);
            }
            account.state = Some(state);
            state_override.insert(addr, account);
        }
    }

    let provider = connect(rpc_url).await?;
    let result = provider.call(tx).overrides(state_override).await;

    let calldata_hex = format!("0x{}", hex(&calldata));
    match result {
        Ok(bytes) => Ok(vec![
            Finding::new(
                "engine-evm-simulate-call",
                format!("Call succeeds in simulation: {signature}"),
                "medium",
            )
            .with("confidence", "confirmed")
            .with("layer", "L2")
            .with(
                "description",
                format!(
                    "eth_call with storage overrides returned successfully. The call path \
                     works under the hypothesized state — the attack premise is confirmed \
                     by simulation, no transaction was broadcast."
                ),
            )
            .with(
                "evidence",
                format!("to={to} calldata={calldata_hex} result=0x{}", hex(&bytes)),
            ),
        ]),
        Err(e) => Ok(vec![
            Finding::new(
                "engine-evm-simulate-call",
                format!("Call reverts in simulation: {signature}"),
                "info",
            )
            .with("confidence", "confirmed")
            .with("layer", "L2")
            .with(
                "description",
                "eth_call with storage overrides reverted — the hypothesized state does \
                 not make this call path viable (or the call itself is not callable via \
                 eth_call).",
            )
            .with("evidence", format!("to={to} calldata={calldata_hex} error={e}")),
        ]),
    }
}

/// oracle-staleness: call `latestRoundData()` on each feed and compare
/// `updatedAt` against the latest block timestamp. Feeds that stopped
/// updating are the quiet version of oracle compromise (BTV-L4-001).
///
/// options:
///   feeds:                list of aggregator addresses
///   maxStalenessSeconds:  staleness threshold (default 3600)
pub async fn oracle_staleness(
    rpc_url: &str,
    feeds: &[String],
    max_staleness: u64,
) -> anyhow::Result<Vec<Finding>> {
    let provider = connect(rpc_url).await?;
    let block = provider
        .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
        .await?
        .ok_or_else(|| anyhow::anyhow!("latest block not found"))?;
    let block_ts = block.header.timestamp;

    let mut findings = Vec::new();
    for raw in feeds {
        let Ok(address) = raw.parse::<Address>() else {
            continue;
        };
        // calldata = selector("latestRoundData()") — no arguments.
        let calldata = selector("latestRoundData()").to_vec();
        let mut tx = TransactionRequest::default();
        tx.set_to(address);
        tx.set_input(Bytes::from(calldata));

        let result: Result<Bytes, _> = provider.call(tx).await;
        let Ok(res) = result else {
            findings.push(
                Finding::new(
                    "engine-evm-oracle-staleness",
                    format!("Feed does not implement latestRoundData(): {raw}"),
                    "info",
                )
                .with("layer", "L4")
                .with("description", "eth_call to latestRoundData() reverted; the feed uses another interface (e.g. legacy latestAnswer).")
                .with("target", raw.clone()),
            );
            continue;
        };
        if res.len() < 160 {
            findings.push(
                Finding::new(
                    "engine-evm-oracle-staleness",
                    format!("Unexpected latestRoundData() return size from {raw}"),
                    "low",
                )
                .with("layer", "L4")
                .with("evidence", format!("return_size={}", res.len()))
                .with("target", raw.clone()),
            );
            continue;
        }

        // latestRoundData() returns (roundId, answer, startedAt, updatedAt,
        // answeredInRound) — 5 x 32-byte words.
        let answer = U256::from_be_bytes::<32>(res[32..64].try_into().unwrap());
        let updated_at = U256::from_be_bytes::<32>(res[96..128].try_into().unwrap());
        let evidence = format!(
            "feed={raw} answer={answer} updatedAt={updated_at} blockTimestamp={block_ts}"
        );

        if answer.is_zero() {
            findings.push(
                Finding::new("engine-evm-oracle-staleness", "Oracle feed reporting zero", "critical")
                    .with("confidence", "confirmed")
                    .with("layer", "L4")
                    .with("weakness", "BTV-L4-001")
                    .with(
                        "description",
                        "The aggregator's latest answer is zero — consuming protocols will \
                         misprice assets or break outright (the classic broken-feed incident).",
                    )
                    .with("evidence", evidence),
            );
            continue;
        }

        let staleness = block_ts.saturating_sub(updated_at.to::<u64>());
        if staleness > max_staleness {
            findings.push(
                Finding::new(
                    "engine-evm-oracle-staleness",
                    format!("Stale oracle feed: last update {staleness}s ago (threshold {max_staleness}s)"),
                    "high",
                )
                .with("confidence", "confirmed")
                .with("layer", "L4")
                .with("weakness", "BTV-L4-001")
                .with(
                    "description",
                    "The feed stopped updating. Protocols consuming it act on stale prices — \
                     a quiet failure mode that precedes many oracle incidents.",
                )
                .with("evidence", evidence),
            );
        } else {
            findings.push(
                Finding::new(
                    "engine-evm-oracle-staleness",
                    format!("Oracle feed fresh (staleness {staleness}s)"),
                    "info",
                )
                .with("confidence", "confirmed")
                .with("layer", "L4")
                .with("evidence", evidence),
            );
        }
    }
    Ok(findings)
}

/// erc20-balance: read `balanceOf(account)` on an ERC-20 via eth_call —
/// used for token profit verification in incident replays.
///
/// options:
///   token:     ERC-20 address
///   accounts:  list of account addresses
///   minProfit: optional decimal threshold; a balance at or above it is
///              reported as a critical confirmed profit finding
pub async fn erc20_balance(
    rpc_url: &str,
    token: &str,
    accounts: &[String],
    min_profit: Option<U256>,
) -> anyhow::Result<Vec<Finding>> {
    let token: Address = token
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid token address {token}: {e}"))?;
    let provider = connect(rpc_url).await?;

    // calldata prefix = selector("balanceOf(address)")
    let prefix = encode_calldata("balanceOf(address)", &[])?;
    let mut findings = Vec::new();
    for raw in accounts {
        let account: Address = raw
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid account address {raw}: {e}"))?;
        let mut call = prefix.clone();
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(account.as_slice());
        call.extend_from_slice(&word);

        let mut tx = TransactionRequest::default();
        tx.set_to(token);
        tx.set_input(Bytes::from(call));
        let result: Result<Bytes, _> = provider.call(tx).await;
        match result {
            Ok(res) if res.len() >= 32 => {
                let balance = U256::from_be_bytes::<32>(res[..32].try_into().unwrap());
                let is_profit = min_profit.map_or(false, |min| balance >= min);
                let (id, title, severity) = if is_profit {
                    (
                        "engine-evm-erc20-profit",
                        format!("Token profit verified: {raw}"),
                        "critical",
                    )
                } else {
                    (
                        "engine-evm-erc20-balance",
                        format!("ERC-20 balance: {raw}"),
                        "info",
                    )
                };
                findings.push(
                    Finding::new(id, title, severity)
                        .with("confidence", "confirmed")
                        .with("layer", "L5")
                        .with("target", raw.clone())
                        .with(
                            "description",
                            if is_profit {
                                "The account's token balance reached the declared profit \
                                 threshold — the replay's economic objective was achieved."
                                    .to_string()
                            } else {
                                String::new()
                            },
                        )
                        .with(
                            "evidence",
                            format!("token={token} account={raw} balance={balance}"),
                        ),
                );
            }
            Ok(_) => findings.push(
                Finding::new(
                    "engine-evm-erc20-balance",
                    format!("Short return from balanceOf for {raw}"),
                    "low",
                )
                .with("target", raw.clone()),
            ),
            Err(e) => findings.push(
                Finding::new(
                    "engine-evm-erc20-balance",
                    format!("balanceOf call failed for {raw}"),
                    "low",
                )
                .with("target", raw.clone())
                .with("description", e.to_string()),
            ),
        }
    }
    Ok(findings)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_selectors_match_reference_values() {
        // Chainlink latestAnswer() and Uniswap V2 getReserves() have
        // well-known selectors; keccak must reproduce them.
        assert_eq!(selector("latestAnswer()"), [0x50, 0xd2, 0x5b, 0xcd]);
        assert_eq!(selector("getReserves()"), [0x09, 0x02, 0xf1, 0xac]);
        assert_eq!(selector("latestRoundData()"), [0xfe, 0xaf, 0x96, 0x8c]);
    }

    #[test]
    fn scan_finds_selector_in_synthetic_bytecode() {
        // Fabricated bytecode containing the latestAnswer selector.
        let code: Vec<u8> = vec![0x60, 0x00, 0x50, 0xd2, 0x5b, 0xcd, 0x56, 0xfd];
        let hits = scan_code(&code);
        assert!(hits.iter().any(|(sig, _)| *sig == "latestAnswer()"));
        assert!(!hits.iter().any(|(sig, _)| *sig == "getReserves()"));
    }

    #[test]
    fn scan_ignores_clean_bytecode() {
        let code: Vec<u8> = vec![0x60, 0x01, 0x60, 0x02, 0x01, 0x00];
        assert!(scan_code(&code).is_empty());
    }

    #[test]
    fn calldata_encoding_matches_reference() {
        // Reference: `cast calldata "borrow(uint256)" 16000000000000000000`
        let calldata = encode_calldata(
            "borrow(uint256)",
            &[U256::from(16_000_000_000_000_000_000u128)],
        )
        .unwrap();
        assert_eq!(
            hex(&calldata),
            "c5ebeaec000000000000000000000000000000000000000000000000de0b6b3a76400000"
        );
    }

    #[test]
    fn u256_parsing_accepts_decimal_and_hex() {
        assert_eq!(
            parse_u256("16000000000000000000").unwrap(),
            U256::from(16_000_000_000_000_000_000u128)
        );
        assert_eq!(
            parse_u256("0xde0b6b3a76400000").unwrap(),
            U256::from(16_000_000_000_000_000_000u128)
        );
    }

    #[test]
    fn balanceof_calldata_matches_reference() {
        // balanceOf(address) selector is the well-known 0x70a08231;
        // the argument is the address right-aligned in one 32-byte word.
        let calldata = encode_calldata("balanceOf(address)", &[]).unwrap();
        assert_eq!(hex(&calldata), "70a08231");
    }
}
