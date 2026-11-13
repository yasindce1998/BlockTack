//! Engine actions: the real chain-facing capabilities of BlockTack.

use crate::finding::Finding;
use alloy::eips::BlockId;
use alloy::primitives::{keccak256, Address, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};

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
}
