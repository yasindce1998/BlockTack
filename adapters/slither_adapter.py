#!/usr/bin/env python3
"""Slither adapter: runs Slither over the target's contract sources and
converts its SARIF output into BlockTack findings (layer L2).

Requires slither-analyzer installed:  pip install slither-analyzer
"""
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from btadapter import main

LEVEL_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


def run(target: dict, options: dict) -> list:
    sources = [c["sourceDir"] for c in target.get("contracts", []) if c.get("sourceDir")]
    if not sources:
        return [{
            "id": "slither-no-sources",
            "title": "No contract sources configured",
            "severity": "info",
            "layer": "L2",
            "source": "slither",
            "description": "Target has no contracts with sourceDir; nothing to scan.",
        }]

    findings = []
    with tempfile.TemporaryDirectory() as tmp:
        for src in sources:
            out = os.path.join(tmp, os.path.basename(src.rstrip("/")) + ".sarif")
            proc = subprocess.run(
                ["slither", src, "--sarif", out],
                capture_output=True,
                text=True,
            )
            if not os.path.exists(out):
                findings.append({
                    "id": "slither-failed",
                    "title": f"Slither failed on {src}",
                    "severity": "info",
                    "layer": "L2",
                    "source": "slither",
                    "description": (proc.stderr or proc.stdout)[-800:],
                })
                continue
            with open(out) as fh:
                sarif = json.load(fh)
            for run in sarif.get("runs", []):
                for res in run.get("results", []):
                    text = res.get("message", {}).get("text", "")
                    findings.append({
                        "id": res.get("ruleId", "slither"),
                        "title": text[:160] or "Slither finding",
                        "severity": LEVEL_SEVERITY.get(res.get("level", "note"), "info"),
                        "confidence": "medium",
                        "layer": "L2",
                        "weakness": res.get("ruleId", ""),
                        "source": "slither",
                    })
    return findings


if __name__ == "__main__":
    main(run)
