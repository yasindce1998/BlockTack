//! BlockTack Solana attack engine.
//!
//! Speaks the same job/findings contract as engine-evm: reads a JSON job
//! from stdin (`{"action", "options", "target"}`) and writes a JSON
//! array of BlockTack findings to stdout. Uses Solana's JSON-RPC
//! directly — no Solana SDK dependency.
//!
//! Implemented actions:
//!   fingerprint  — node version, epoch/slot, genesis hash
//!   balance      — lamports of an account (exploit PnL tracking)

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
    endpoints: Vec<Endpoint>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Endpoint {
    #[serde(default)]
    role: Option<String>,
    url: String,
}

fn rpc_url(job: &Job) -> Option<&str> {
    job.target
        .endpoints
        .iter()
        .find(|e| e.role.as_deref().unwrap_or("rpc") == "rpc")
        .map(|e| e.url.as_str())
}

/// json_rpc posts a Solana JSON-RPC request and returns the `result`.
fn json_rpc(url: &str, method: &str, params: Value) -> Result<Value, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;
    let body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let resp: Value = client
        .post(url)
        .json(&body)
        .send()
        .map_err(|e| format!("transport: {e}"))?
        .json()
        .map_err(|e| format!("decode: {e}"))?;
    if let Some(err) = resp.get("error") {
        return Err(err.to_string());
    }
    Ok(resp.get("result").cloned().unwrap_or(Value::Null))
}

fn finding(id: &str, title: &str, severity: &str) -> Value {
    serde_json::json!({
        "id": id,
        "title": title,
        "severity": severity,
        "confidence": "confirmed",
        "layer": "L1",
        "source": "engine-solana",
    })
}

fn fingerprint(url: &str) -> Vec<Value> {
    let mut findings = Vec::new();
    match json_rpc(url, "getVersion", Value::Null) {
        Ok(version) => {
            findings.push(serde_json::json!({
                "id": "engine-solana-fingerprint",
                "title": "Solana node fingerprinted",
                "severity": "info",
                "confidence": "confirmed",
                "layer": "L1",
                "weakness": "BTV-L1-001",
                "description": "Node identity established via getVersion. Cross-reference the \
                                solana-core version with known validator CVEs and outage \
                                postmortems before attacking protocol handlers.",
                "evidence": version.to_string(),
                "source": "engine-solana",
            }));
        }
        Err(e) => {
            findings.push(finding(
                "engine-solana-fingerprint-failed",
                &format!("getVersion failed: {e}"),
                "info",
            ));
        }
    }
    match json_rpc(url, "getEpochInfo", Value::Null) {
        Ok(epoch) => {
            findings.push(serde_json::json!({
                "id": "engine-solana-epoch",
                "title": "Epoch and slot state discovered",
                "severity": "info",
                "confidence": "confirmed",
                "layer": "L1",
                "description": "Epoch/slot state via getEpochInfo — establishes the consensus \
                                timeline for stake and validator analysis.",
                "evidence": epoch.to_string(),
                "source": "engine-solana",
            }));
        }
        Err(e) => {
            findings.push(finding(
                "engine-solana-epoch-failed",
                &format!("getEpochInfo failed: {e}"),
                "info",
            ));
        }
    }
    findings
}

fn balance(url: &str, account: &str) -> Vec<Value> {
    match json_rpc(
        url,
        "getBalance",
        serde_json::json!([account]),
    ) {
        Ok(res) => {
            let lamports = res.get("value").and_then(Value::as_u64).unwrap_or(0);
            vec![serde_json::json!({
                "id": "engine-solana-balance",
                "title": format!("Account balance: {lamports} lamports"),
                "severity": "info",
                "confidence": "confirmed",
                "layer": "L5",
                "description": "Balance of the tracked account — used for exploit PnL \
                                verification on Solana (1 SOL = 1e9 lamports).",
                "evidence": format!("account={account} lamports={lamports}"),
                "target": account,
                "source": "engine-solana",
            })]
        }
        Err(e) => vec![finding(
            "engine-solana-balance-failed",
            &format!("getBalance failed: {e}"),
            "info",
        )],
    }
}

fn main() {
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("engine-solana: failed to read job: {e}");
        std::process::exit(1);
    }
    let job: Job = match serde_json::from_str(&input) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("engine-solana: invalid job JSON: {e}");
            std::process::exit(1);
        }
    };

    let findings = match rpc_url(&job) {
        None => vec![finding(
            "engine-solana-no-rpc",
            "No RPC endpoint in target",
            "medium",
        )],
        Some(url) => match job.action.as_str() {
            "fingerprint" => fingerprint(url),
            "balance" => match job.options.get("account").and_then(Value::as_str) {
                Some(account) => balance(url, account),
                None => vec![finding(
                    "engine-solana-balance-args",
                    "balance action requires options.account",
                    "low",
                )],
            },
            other => vec![finding(
                "engine-solana-unknown",
                &format!("action `{other}` is not implemented yet"),
                "info",
            )],
        },
    };

    let mut stdout = std::io::stdout().lock();
    let _ = serde_json::to_writer_pretty(&mut stdout, &findings);
    let _ = writeln!(stdout);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_get_version_result() {
        // Shape of a real getVersion response result.
        let raw: Value = serde_json::from_str(
            r#"{"jsonrpc":"2.0","result":{"solana-core":"2.1.0","feature-set":1234},"id":1}"#,
        )
        .map(|doc: Value| doc["result"].clone())
        .unwrap();
        assert_eq!(raw["solana-core"].as_str().unwrap(), "2.1.0");
    }

    #[test]
    fn parses_epoch_info_result() {
        let doc: Value = serde_json::from_str(
            r#"{"jsonrpc":"2.0","result":{"absoluteSlot":1234,"epoch":56,"slotIndex":10,"slotsInEpoch":432000},"id":1}"#,
        )
        .unwrap();
        let result = &doc["result"];
        assert_eq!(result["epoch"].as_u64().unwrap(), 56);
        assert_eq!(result["absoluteSlot"].as_u64().unwrap(), 1234);
    }

    #[test]
    fn balance_finding_carries_lamports() {
        let fs = balance("http://127.0.0.1:1", "DeadBeef");
        // Unreachable endpoint -> info failure finding, not a crash.
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0]["severity"].as_str().unwrap(), "info");
    }
}
