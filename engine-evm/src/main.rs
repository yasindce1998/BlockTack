//! BlockTack EVM attack engine.
//!
//! Contract: reads a JSON job from stdin and writes a JSON array of
//! BlockTack findings to stdout. The job has the shape
//!
//!   {"action": "...", "options": {...}, "target": {...}}
//!
//! Implemented actions:
//!   fingerprint  — chain identity (chain ID, head, client version)
//!   map-oracles  — scan deployed bytecode for oracle selectors
//!   verify-pnl   — balance-delta verification of exploit profit

mod actions;
mod finding;

use finding::Finding;
use serde::Deserialize;
use serde_json::Value;
use std::io::{Read, Write};

#[derive(Deserialize)]
struct Job {
    action: String,
    #[serde(default)]
    options: Value,
    #[serde(default)]
    target: TargetSpec,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct TargetSpec {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    endpoints: Vec<Endpoint>,
    #[serde(default)]
    contracts: Vec<ContractSpec>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Endpoint {
    #[serde(default)]
    role: Option<String>,
    url: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContractSpec {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    address: Option<String>,
}

/// The first RPC endpoint of the target.
fn rpc_url(job: &Job) -> anyhow::Result<&str> {
    job.target
        .endpoints
        .iter()
        .find(|e| e.role.as_deref().unwrap_or("rpc") == "rpc")
        .map(|e| e.url.as_str())
        .ok_or_else(|| anyhow::anyhow!("target has no rpc endpoint"))
}

/// Addresses to scan: job options first, then the target's contracts.
fn collect_addresses(job: &Job) -> Vec<String> {
    let mut addresses = Vec::new();
    if let Some(list) = job.options.get("addresses").and_then(Value::as_array) {
        addresses.extend(list.iter().filter_map(Value::as_str).map(str::to_string));
    }
    if addresses.is_empty() {
        addresses.extend(
            job.target
                .contracts
                .iter()
                .filter_map(|c| c.address.clone()),
        );
    }
    addresses
}

fn stub_finding(action: &str, note: &str) -> Finding {
    Finding::new(
        &format!("engine-evm-{action}"),
        &format!("action `{action}` is a stub"),
        "info",
    )
    .with("confidence", "high")
    .with("layer", "L2")
    .with(
        "description",
        format!("{note} Not implemented yet — see docs/roadmap.md."),
    )
}

async fn dispatch(job: Job) -> Vec<Finding> {
    let action = job.action.as_str();
    let url = match rpc_url(&job) {
        Ok(url) => url.to_string(),
        Err(e) => {
            return vec![Finding::new(
                "engine-evm-no-rpc",
                "No RPC endpoint in target",
                "medium",
            )
            .with("description", e.to_string())]
        }
    };

    let result: anyhow::Result<Vec<Finding>> = match action {
        "fingerprint" => async {
            let provider = actions::connect(&url).await?;
            actions::fingerprint(provider).await
        }
        .await,
        "map-oracles" => async {
            let provider = actions::connect(&url).await?;
            actions::map_oracles(provider, &collect_addresses(&job)).await
        }
        .await,
        "verify-pnl" => match job.options.get("attacker").and_then(Value::as_str) {
            Some(attacker) => {
                let blocks_ago = job
                    .options
                    .get("blocksAgo")
                    .and_then(Value::as_u64)
                    .unwrap_or(2);
                async {
                    actions::verify_pnl(&url, attacker, blocks_ago).await
                }
                .await
            }
            None => Ok(vec![Finding::new(
                "engine-evm-verify-pnl",
                "verify-pnl requires options.attacker",
                "low",
            )
            .with(
                "description",
                "Pass the attacker address via the playbook step options: \
                 {attacker: \"0x..\", blocksAgo: N}",
            )]),
        },
        other => Ok(vec![stub_finding(
            other,
            "Unknown action requested.",
        )]),
    };

    result.unwrap_or_else(|e| {
        vec![Finding::new(
            "engine-evm-error",
            format!("action `{action}` failed"),
            "info",
        )
        .with("description", e.to_string())]
    })
}

fn main() {
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("engine-evm: failed to read job: {e}");
        std::process::exit(1);
    }
    let job: Job = match serde_json::from_str(&input) {
        Ok(job) => job,
        Err(e) => {
            eprintln!("engine-evm: invalid job JSON: {e}");
            std::process::exit(1);
        }
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    let findings = rt.block_on(dispatch(job));

    let mut stdout = std::io::stdout().lock();
    let _ = serde_json::to_writer_pretty(&mut stdout, &findings);
    let _ = writeln!(stdout);
}
