#!/usr/bin/env python3
"""BlockTack adapter base module.

Contract: the orchestrator runs

    python3 <adapter>.py --target-file target.json --options-json '{...}' --sarif-out out.sarif

The adapter's run(target, options) returns a list of BlockTack findings
(dicts with the same field names as the Go core.Finding struct). This base
module serializes them into SARIF so the orchestrator can parse them back.
"""
import argparse
import json
import sys

SEVERITY_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}


def run(target: dict, options: dict) -> list:
    """Override in your adapter. Return a list of BlockTack findings."""
    raise NotImplementedError("adapters must implement run(target, options)")


def build_sarif(findings: list) -> dict:
    results = []
    for i, f in enumerate(findings, 1):
        f.setdefault("id", f"adapter-{i}")
        f.setdefault("severity", "info")
        f.setdefault("confidence", "medium")
        title = f.get("title", f["id"])
        description = f.get("description", "")
        text = f"{title}: {description}" if description else title
        props = {
            "blocktack": {k: f.get(k, "") for k in (
                "id", "severity", "confidence", "layer",
                "weakness", "target", "evidence", "poc", "source",
            )}
        }
        results.append({
            "ruleId": f.get("weakness") or f["id"],
            "level": SEVERITY_LEVEL.get(f["severity"], "none"),
            "message": {"text": text[:4000]},
            "properties": props,
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "blocktack-adapter"}},
            "results": results,
        }],
    }


def main(adapter_run=run):
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-file", required=True, help="target JSON produced by the orchestrator")
    ap.add_argument("--options-json", default="{}", help="free-form options from the playbook step")
    ap.add_argument("--sarif-out", help="write SARIF here (default: stdout)")
    ns = ap.parse_args()

    with open(ns.target_file) as fh:
        target = json.load(fh)
    options = json.loads(ns.options_json or "{}")

    findings = adapter_run(target, options) or []
    sarif = build_sarif(findings)

    if ns.sarif_out:
        with open(ns.sarif_out, "w") as fh:
            json.dump(sarif, fh, indent=2)
    else:
        json.dump(sarif, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
