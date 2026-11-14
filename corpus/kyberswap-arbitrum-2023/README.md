# KyberSwap Elastic — Arbitrum One (2023-11-22)

Replay corpus for the **Arbitrum One component** of the KyberSwap Elastic
exploit (~$47M multi-chain over Nov 21–23 2023; the largest single-chain
chunk, ~$20M+, landed on Arbitrum One).

**Verdict: reproduced end-to-end.** All 12 attacker transactions
re-execute on a local anvil fork with **status=1 and identical
hashes**, and the profit materializes on the profit holder.
`corpus/manifest.yaml` tracks this entry as `reproduced`.

- Weakness: BTV-L2-011 — concentrated-liquidity tick-rounding math in
  KyberSwap Elastic pools (same root cause as the mainnet replay in
  `corpus/kyberswap-2023/`)
- Fork block: **153081940** (2023-11-22 22:56 UTC) — 8 blocks before
  the attacker's deployment; at this block the attacker EOA
  (`0x50275e0b7261559ce1644014d4b78d4aa63be836`) is at **nonce 0** with
  its historical **2 ETH balance already in the fork state** (no cheat
  codes needed), and all target pools are pre-attack
- Transactions: 12 vendored raw signed txs (nonces 0–11, blocks
  153081948–153085624): 2 attack-contract deployments + 10 attack
  batches. Three later EOA txs (nonces 12–14, fund shuffling on
  Nov 23 / Dec 1) are documented in `transactions.yaml` but not
  replayed — they post-date all profit realization
- Profit holder: `0xc9b826bad20872eb29f9b1d8af4befe8460b50c6` (same
  account as the mainnet replay)
- Attack contracts: `0xe84e1e5b…62fadf1` (CREATE at nonce 0) and
  `0x5e5c2dba…2ee2b5ae` (CREATE at nonce 6)

Zero transactions touch Arbitrum One; everything broadcasts to the
local fork only. Public RPCs are used read-only (archive state and tx
objects).

## Run it

```sh
bin/blocktack campaign \
  --target corpus/kyberswap-arbitrum-2023/target.yaml \
  --playbook playbooks/evm/kyberswap-arbitrum-incident-replay.yaml
```

The playbook starts the pacing/caching fork proxy (`rpc_proxy.py`,
port 8559) and the anvil fork (port 8558) itself.

**Expect a slow first run.** A fresh anvil fork of Arbitrum One lazily
fetches Nov-2023 archive state — ~4,100 RPC calls across the replay,
with single attack txs taking up to ~15 minutes cold. The proxy
disk-caches deterministic state calls into `rpc_cache/` (gitignored),
so reruns and anvil restarts are cheap. Anvil forks inherit the remote
chainId (42161) and state; no funding or cheat setup is required.

## Profit evidence (fork vs on-chain record at block 153086000)

The on-chain record (`onchain_profit_record.json`) was read from
Arbitrum One via `eth_getLog` transfer queries on the profit holder.
13 of 15 profit tokens match the replay **to the raw unit**:

| Token | Address | On-chain record (raw units) | Replay |
|---|---|---:|---|
| ARB | `0x912ce591…6548` | 3,987,331,660,828,138,952,727,409 | exact |
| DAI | `0xda10009c…0da1` | 826,527,815,755,108,067,660,638 | exact |
| KNC | `0xe4dddfe6…01cb` | 368,092,883,147,477,728,715,549 | exact |
| ELK | `0xeeeeeb57…eeee` | 65,284,693,429,318,374,061,752 | exact |
| GMX | `0xfc5a1a6e…ad0a` | 4,230,724,243,665,096,784,297 | exact |
| LINK | `0xf97f4df7…fb4` | 1,489,139,431,686,715,895,642 | exact |
| wstETH | `0x5979d7b5…0529` | 870,031,236,388,271,794,641 | exact |
| axl-wstETH | `0x9cfb13e6…36e4` | 343,801,788,521,031,917,582 | exact |
| STG | `0x6694340f…1eb6` | 325,130,403,496,296,320,415 | exact |
| swETH | `0xbc011a12…cf18` | 49,557,572,890,290,081,987 | exact |
| SWTH | `0xf763fa32…b633` | 1,254,865,865,438,514 | exact |
| axlUSDC | `0xeb466342…5215` | 396,445,433,736 | exact |
| fUSDC | `0x4cfa50b7…2b2a` | 14,501,617,692 | exact |
| WETH | `0x82af4944…bab1` | 5,524,172,935,832,064,631,336 | **+120.6 WETH (+2.2%)** |
| WBTC | `0x2f2a2543…5b0f` | 1,300,783,682 (8 dp) | **+11,957,368 raw (+0.9%)** |

WETH and WBTC come out **slightly above** the on-chain record. Cause,
identified with evidence: ~130 competing arbitrage transactions touched
the same pools between the attacker's transactions on the real chain
(e.g. bot `0x9d17b4e3…` arbing WETH↔ARB through pool `0xc6f78049…` at
block 153081959). A single-actor replay excludes them, so the fork
retains the slice the competitors took on the real chain. This is an
inherent property of single-actor replay on a busy L2, not a defect;
replaying those competing txs too would close the gap to the wei.

## Known divergences

- **`gasUsed` differs from Arbitrum receipts** — Nitro bills L1 calldata
  into the L2 `gasUsed`; plain anvil charges only EVM gas. Tx status,
  hashes, and post-state are unaffected.
- **WETH profit varies slightly run-to-run** (~±1 WETH observed across
  validated runs: 5,648.42 / 5,649.28 WETH) on top of the competing-arb
  divergence — the fork automines each tx into a fresh block whose
  timestamp differs from the historical one, and Elastic's per-second
  fee math is timestamp-sensitive. ARB/DAI/KNC/axlUSDC are exact on
  every run; the playbook's WETH threshold accounts for the spread.
- **Arbiscan "Error" badges** on some attack txs are internal markers,
  not failures — every tx receipt has `status=1`.
- No Arbitrum precompiles are involved (verified: bytecode scan + the
  plain-EVM replay succeeds), so plain anvil re-executes the sequence
  deterministically.

## Files

- `transactions/NN_<hash>.raw` — 12 keccak-verified signed transactions
  (`00`–`11`, nonce order)
- `transactions.yaml` — ordered tx list with blocks, actors, and the
  3 post-exploit nonces
- `tx_hashes.txt` — the 12 hashes, one per line (provenance input)
- `fetch-raw-txs.sh` — provenance check: re-derives every raw tx from
  Arbitrum RPCs and compares bytes. The raw-RPC path is keccak-gated
  (meowrpc load-balances across nodes that disagree on raw-tx
  serialization); the fallback RLP-reconstructs from the on-chain tx
  object served by `arb1.arbitrum.io/rpc` (`reconstruct_raw.py`).
  Verified 12/12 byte-exact (2026-11-14).
- `reconstruct_raw.py` — deterministic RLP reconstruction of raw txs
  from tx objects (type 0/1/2)
- `rpc_proxy.py` — pacing/caching fork proxy (port 8559 → nodies.app by
  default) so anvil's burst fetches survive a public-tier RPC;
  disk-caches deterministic state calls in `rpc_cache/` (gitignored)
- `replay.sh` — resumable replay driver used by the playbook (send raw
  → poll receipt; fails on revert/timeout)
- `onchain_profit_record.json` — per-token profit holder balances read
  from Arbitrum One (the verification ground truth)
- `target.yaml` — the mainnet-fork target for the campaign

## RPCs (validated 2026-11-13/14)

| Purpose | URL | Notes |
|---|---|---|
| Fork (archive state) | `https://arbitrum-one-public.nodies.app` | archive incl. Nov-2023 state; reliable **through the pacing proxy**; direct use risks rate-limit stalls |
| Fork (archive state) | `https://arbitrum-one.public.blastapi.io` | archive-capable but **deadlocks anvil under burst** — never use directly |
| Raw txs / tx objects | `https://arb1.arbitrum.io/rpc` | serves full tx objects (incl. signatures) but not `eth_getRawTransactionByHash`; used for RLP reconstruction |
| Raw txs | `https://arbitrum.meowrpc.com` | serves raws but **non-deterministically** (nodes disagree on serialization) — raws are only accepted when keccak-gated |

## Provenance

Raw transactions were reconstructed RLP-deterministically from the
on-chain tx objects and verified with `keccak256(raw) == tx hash`, then
byte-compared against independent raw-serving RPCs. Re-run:

```sh
corpus/kyberswap-arbitrum-2023/fetch-raw-txs.sh
```
