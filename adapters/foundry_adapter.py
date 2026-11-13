#!/usr/bin/env python3
"""Foundry adapter: runs forge build/test on the target's sources and
converts results into BlockTack findings (layer L2).

Semantics for an offensive platform:
  - a *passing* test whose name matches (poc|exploit|attack) is a
    CONFIRMED finding — the PoC demonstrates the vulnerability
  - a *failing* poc/exploit test is informational (target may be patched,
    or the harness is broken)
  - any other failing test is a low-severity regression signal
  - build errors are high-severity findings (target does not compile)

Requires foundry installed: https://getfoundry.sh
"""
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from btadapter import main

POC_PATTERN = re.compile(r"(poc|exploit|attack)", re.IGNORECASE)


def run(target: dict, options: dict) -> list:
    source_dir = options.get("sourceDir")
    if not source_dir:
        source_dir = next(
            (c["sourceDir"] for c in target.get("contracts", []) if c.get("sourceDir")),
            None,
        )
    if not source_dir:
        return [{
            "id": "foundry-no-sources",
            "title": "No contract sources configured",
            "severity": "info",
            "layer": "L2",
            "source": "foundry",
            "description": "Target has no contracts with sourceDir; nothing to build or test.",
        }]

    findings = []

    # --- build ---
    build = subprocess.run(
        ["forge", "build", "--json"],
        cwd=source_dir,
        capture_output=True,
        text=True,
    )
    build_errors = _parse_build(build.stdout)
    for err in build_errors[:20]:
        message = err.get("message", "compilation error")[:800]
        file_hint = ""
        loc = err.get("sourceLocation") or {}
        if loc.get("file"):
            file_hint = f" ({loc['file']})"
        if err.get("severity") == "error":
            findings.append({
                "id": "foundry-build-error",
                "title": "Build error in target sources",
                "severity": "high",
                "layer": "L2",
                "source": "foundry",
                "description": message,
            })
        else:
            # Compiler warnings. Solc 9302 (unused low-level call return
            # value) is a genuine vulnerability signal: BTV-L2-005.
            is_unchecked_call = "Return value of low-level calls not used" in message
            findings.append({
                "id": "foundry-build-warning",
                "title": f"Compiler warning{file_hint}",
                "severity": "medium" if is_unchecked_call else "low",
                "layer": "L2",
                "weakness": "BTV-L2-005" if is_unchecked_call else "",
                "source": "foundry",
                "description": message + (
                    " Unchecked low-level calls are a classic reentrancy and "
                    "silent-failure pattern (BTV-L2-005)."
                    if is_unchecked_call else ""
                ),
            })

    # --- test ---
    test = subprocess.run(
        ["forge", "test", "--json"],
        cwd=source_dir,
        capture_output=True,
        text=True,
    )
    suites = _parse_suites(test.stdout)
    weakness_by_suite = options.get("weaknessBySuite") or {}
    for suite, testcases in suites.items():
        for name, case in testcases.items():
            success = case.get("success", False)
            is_poc = bool(POC_PATTERN.search(name))
            weakness = options.get("weakness", "")
            for fragment, w in weakness_by_suite.items():
                if fragment in suite:
                    weakness = w
                    break
            if is_poc and success:
                findings.append({
                    "id": f"foundry-poc-{suite}-{name}",
                    "title": f"PoC passed: {name}",
                    "severity": "critical",
                    "confidence": "confirmed",
                    "layer": "L2",
                    "weakness": weakness,
                    "source": "foundry",
                    "description": (
                        f"Exploit PoC {name} in {suite} passed — the vulnerability "
                        "was reproduced by executing the attack in a controlled "
                        "foundry EVM."
                    ),
                    "evidence": f"forge test --json {suite}::{name} success",
                    "poc": f"cd {source_dir} && forge test -m {name}",
                })
            elif is_poc and not success:
                findings.append({
                    "id": f"foundry-poc-{suite}-{name}",
                    "title": f"PoC failed: {name}",
                    "severity": "info",
                    "layer": "L2",
                    "source": "foundry",
                    "description": (
                        f"Exploit PoC {name} in {suite} did not pass — either the "
                        f"target is patched or the harness is broken. Reason: "
                        f"{case.get('reason', 'unknown')}"
                    ),
                })
            elif not success:
                findings.append({
                    "id": f"foundry-test-{suite}-{name}",
                    "title": f"Failing test: {name}",
                    "severity": "low",
                    "layer": "L2",
                    "source": "foundry",
                    "description": f"{name} in {suite} failed: {case.get('reason', 'unknown')}",
                })

    if not findings:
        findings.append({
            "id": "foundry-clean",
            "title": "Build and tests clean; no PoC tests present",
            "severity": "info",
            "layer": "L2",
            "source": "foundry",
            "description": "forge build and forge test completed without findings. Add PoC tests (test_poc_*) to demonstrate vulnerabilities.",
        })
    return findings


def _parse_build(stdout: str) -> list:
    try:
        doc = json.loads(stdout)
        return doc.get("errors") or []
    except (json.JSONDecodeError, TypeError):
        return []


def _parse_suites(stdout: str) -> dict:
    """Return {suite: {testcase: case}} from `forge test --json` output.

    Handles both the older format ({"suites": {suite: {"testcases":
    {name: {"success": bool}}}}}) and foundry 1.9+ (top-level {suite:
    {"test_results": {name: {"status": "Success"|"Failure"}}}}).
    """
    try:
        doc = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        return {}
    raw = doc.get("suites") if isinstance(doc.get("suites"), dict) else doc
    if not isinstance(raw, dict):
        return {}
    out = {}
    for suite, info in raw.items():
        if not isinstance(info, dict):
            continue
        cases = info.get("test_results") or info.get("testcases") or {}
        if not isinstance(cases, dict):
            continue
        normalized = {}
        for name, case in cases.items():
            if not isinstance(case, dict):
                continue
            if "success" not in case and "status" in case:
                case = dict(case, success=str(case.get("status", "")).lower() == "success")
            normalized[name] = case
        out[suite] = normalized
    return out


if __name__ == "__main__":
    main(run)
