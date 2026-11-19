# Cork Protocol — Uniswap v4 hook exploit (2025-05-28)

Replay corpus for the **Cork Protocol exploit** (~$12M / 3,761.88 wstETH
drained from the wstETH:weETH Liquidity Vault) — the flagship
**Uniswap v4 hook access-control incident** (BTV-L2-015) and the first
corpus entry replaying an exploit that chains a protocol-side economic
edge case with a hook-spoofing attack.

**Verdict: reproduced end-to-end, exactly.** The complete 36-transaction
attack window (attacker + Cork keeper + funder, interleaved) replays on
a local anvil fork with historical-timestamp pinning, and the terminal
state matches mainnet **to the wei**:

| Gate | Mainnet | Fork replay | Delta |
|---|---:|---:|---|
| Exploiter C2 wstETH after exploit | 3,761.877955369549831945 | same | **0 wei** |
| ModuleCore wstETH after exploit | 34.474759349606697572 | same | **0 wei** |
| Gas: LV rebalance / skew / rollover / exploit | 477,912 / 2,225,451 / 4,858,959 / 7,946,138 | same | **byte-exact** |

## The kill chain

Two chained vectors (per the official post-mortem, corrected against
chain data):

1. **Rollover pricing exploit (Cover Token extraction)** — Cork's
   rollover prices the next expiry from a volume-weighted historical
   risk premium (HIYA). ~19 minutes before expiry, the attacker bought
   2.558 DS for 0.0034 wstETH, producing a 1,779-quadrillion-percent
   risk premium that dominated the HIYA. The Liquidity Vault's
   automated rollover then initialized the expiry-2 AMM at
   RA:CT = 2.96e-7 : 3761.25 — letting the attacker buy 3,760.88 CT-2
   for 0.0000029 wstETH.
2. **v4 hook access-control exploit (Depeg Swap extraction)** —
   CorkHook's `beforeSwap` lacked an `onlyPoolManager` guard (the
   upstream `BaseHook` they forked gained it a week after Cork copied
   it). The attacker's contract — itself a v4 hook — spoofed the
   callback flow, passing crafted hookData that made the FlashSwapRouter
   believe the attacker had deposited the router's own unsold DS-2
   reserves: 3,761.25 DS-2 + pCT extracted, then redeemed with the CT-2
   for the vault's wstETH.

## Why the replay is *exact* (not approximate)

The wstETH:weETH market had **zero** non-replayed activity in the
attack window (verified by exhaustive `eth_getLogs` scans of CorkHook,
FlashSwapRouter and ModuleCore). The only inputs are the 36 replayed
transactions. Third-party v4 pools sharing the singleton drifted
−2.11 wstETH in the window; per-pool state is unaffected and the
exploit outcome is wei-identical.

## The 36-transaction attack window

The "2 smart contracts in 2 transactions" from press coverage
undersells the machinery. Chain forensics found:

- **Attacker EOA, nonces 0–13**: funding, a helper contract running
  ~14M gas of pure on-chain computation (address/parameter mining),
  deploys of the two exploiter contracts, the skew, the exploit
- **Cork keeper, nonces 146–165**: factory deployments, three Safe
  executions — including a **ModuleCore implementation upgrade 3 days
  before the exploit** (the rollover only works against the new
  implementation) — and the **expiry rollover** itself (the attack
  depends on this protocol transaction landing between the skew and
  the exploit)
- **Cork funding wallet**: two wstETH transfers funding the keeper's
  LV rebalance (itself a hidden dependency: the rollover reverts
  without the ~0.0102 LP the rebalance mints 6 blocks earlier)

The full ordered list with blocks, pinned timestamps, nonces and roles
is `manifest.json`; the narrative summary is `transactions.yaml`.

## Run it

```sh
bin/blocktack campaign \
  --target corpus/cork-v4hook-2025/target.yaml \
  --playbook playbooks/evm/cork-v4hook-incident-replay.yaml
```

The playbook starts the caching fork proxy (8561) and the anvil fork
(8547, base fee pinned to the fork block's 1.94 gwei), runs the
**hook-audit detection step** against the vulnerable CorkHook on the
pre-exploit fork (the finding a defender could have acted on), then the
timestamp-pinned replay, then hard gates.

**Expect a slow first run**: the cold replay pulls thousands of
archive slots (~25–40 min); the proxy's disk cache (`rpc_cache/`,
gitignored) makes warm reruns 3–5 minutes.

### Timestamp pinning (mandatory)

The attack straddles the market expiry (1748431824). With wall-clock
fork timestamps the skew tx **reverts** (its parameters are hardcoded
for 19-minutes-to-expiry — verified experimentally) and the rollover's
expiry gate never opens. `replay.py` pins each block to its historical
timestamp via `anvil_setNextBlockTimestamp` before broadcasting; this
is what makes the execution byte-identical (gas matches mainnet on all
four critical txs).

### Documented cheats (local-fork only)

1. `anvil_setBalance(keeper, 1 ETH)` — the keeper's fork-block balance
   can't fund ~25M gas of keeper operations
2. `anvil_setNonce(funder, 99 / 107)` before the two funding transfers
   (the funder made 11 unrelated txs in the window)

Keeper rebalances for *other* Cork markets revert against stale fork
state — expected and harmless (nonces consumed, no state written).

## Corrections to the public record (chain-verified)

- The attack window is 36 txs from 3 EOAs, not 2 attacker txs
- The "Exploiter's Proxy Market" and its v4 pool were created **inside
  the exploit tx**, not in a prior setup tx
- The widely-cited CT-2 address has a typo; the correct address is
  `0xcd25aa56aad1bcc1bb4b6b6b08bda53007ec81ce`
- A ModuleCore UUPS upgrade landed 3 days pre-exploit and is a
  required part of the replay

## Files

- `transactions/NN_<hash>.raw` — 36 keccak-verified signed transactions
  (replay order)
- `manifest.json` — machine-readable ordered list (blocks, pinned
  timestamps, nonces, roles)
- `replay.py` — timestamp-pinned replay driver with hard gates
- `fetch-raw-txs.sh` — provenance check (keccak-gated raw fetch from
  publicnode, RLP-reconstruction fallback from drpc tx objects)
- `reconstruct_raw.py` — type 0/1/2/4 RLP reconstruction
- `rpc_proxy.py` — pacing/caching fork proxy (8561 → drpc)
- `target.yaml` — the mainnet-fork target for the campaign
