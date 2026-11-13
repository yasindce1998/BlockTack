//! BlockTack EVM attack engine.
//!
//! Contract: reads a JSON job from stdin and writes a JSON array of
//! BlockTack findings to stdout. The job has the shape
//!
//!   {"action": "...", "options": {...}, "target": {...}}
//!
//! Phase 2 of the roadmap replaces the stubs below with real revm/alloy
//! simulation (fork state manipulation, oracle skew, PnL verification).

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

#[derive(Deserialize)]
#[allow(dead_code)] // options/target are consumed when revm/alloy integration lands
struct Job {
    action: String,
    #[serde(default)]
    options: serde_json::Value,
    #[serde(default)]
    target: serde_json::Value,
}

#[derive(Serialize)]
struct Finding {
    id: String,
    title: String,
    severity: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    confidence: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    layer: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    weakness: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    description: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    evidence: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    target: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    source: String,
}

fn stub_finding(action: &str, note: &str) -> Finding {
    Finding {
        id: format!("engine-evm-{action}"),
        title: format!("action `{action}` is a stub"),
        severity: "info".into(),
        confidence: "high".into(),
        layer: "L2".into(),
        description: format!(
            "{note} This stub proves the engine pipeline end to end; \
             revm/alloy integration lands in Phase 2 of the roadmap."
        ),
        evidence: String::new(),
        target: String::new(),
        source: "engine-evm".into(),
        weakness: String::new(),
    }
}

fn main() {
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("engine-evm: failed to read job: {e}");
        std::process::exit(1);
    }
    let job: Job = match serde_json::from_str(&input) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("engine-evm: invalid job JSON: {e}");
            std::process::exit(1);
        }
    };

    let findings = match job.action.as_str() {
        "map-oracles" => vec![stub_finding(
            &job.action,
            "Map the oracle dependencies of the target contracts (which feeds are read, from which pools).",
        )],
        "oracle-skew" => vec![stub_finding(
            &job.action,
            "Execute a flash-loan funded oracle price skew against the mapped venue.",
        )],
        "verify-pnl" => vec![stub_finding(
            &job.action,
            "Measure attacker profit on the forked environment after the exploit transactions.",
        )],
        other => vec![stub_finding(other, "Unknown action requested.")],
    };

    let mut stdout = std::io::stdout().lock();
    let _ = serde_json::to_writer_pretty(&mut stdout, &findings);
    let _ = writeln!(stdout);
}
