# EIP-7702 sven.eth delegation drain (2026-10-14)

Replay corpus for the **first EIP-7702 wallet-drain incident** in the
BlockTack corpus — the 2026-10-14 single-transaction drain of the EOA
behind **sven.eth** (9.1231 ETH net + 1.69271471 TAPEETH, ~$22.7K),
part of the October 2026 **CrimeEnjoyor** drainer wave (the same
sweeper bytecode took ~$1.54M from a staking user on 2026-10-10).

**Verdict: reproduced end-to-end.** The attacker's single signed type-4
transaction re-executes on a local anvil fork with **status=1 and its
canonical hash**, the victim EOA's code becomes the delegation
designator, and the entire balance is swept. `corpus/manifest.yaml`
tracks this entry as `reproduced`.

- Weakness: **BTV-L2-014 — EIP-7702 malicious delegation** (new
  taxonomy entry in this PR)
- Fork block: **26186934** — the block before the attack: the victim is
  still a **plain EOA** (empty code) holding 9.123657838802131 ETH with
  unclaimed PodMining staking rewards; the sponsor EOA is at nonce 6
- Transaction: **one** vendored raw type-4 tx
  (`0x36e0d149…820ee`, sponsor nonce 6), carrying the victim's
  authorization (auth nonce 7442) delegating to the CrimeEnjoyor
  sweeper at `0x0366b55f…60d1`

## The kill chain (one transaction)

1. The sponsor (attacker EOA `0x9208097c…20bc`) submits a **type-4
   (EIP-7702) transaction** — the victim never pays gas or broadcasts
   anything; only their phished authorization signature is needed
2. The authorization installs the delegation: the victim EOA's code
   becomes `0xef0100 || 0x0366b55f…60d1` (the CrimeEnjoyor sweeper)
3. The sweeper calls `PodMining.claim()`, minting **1.69271471
   TAPEETH** to the victim
4. The sweeper transfers the TAPEETH **victim → sponsor**
5. The sweeper sweeps the victim's **entire 9.123657838802131 ETH**
   balance to the sponsor
6. The delegation **stays installed** after the theft (ExVul flagged it
   as still active at block 26188153) — any future deposit to the
   address remains drainable until revoked

TAPEETH and PodMining themselves are not vulnerable; the entry point is
the delegation on the victim's own address.

## Run it

```sh
bin/blocktack campaign \
  --target corpus/eip7702-sveneth-2026/target.yaml \
  --playbook playbooks/evm/eip7702-sveneth-delegation-drain.yaml
```

The playbook forks mainnet (default archive RPC: drpc; override with
`FORK_URL`) on port 8546 and re-broadcasts the single vendored tx. A
hard gate asserts the receipt status, the delegation designator on the
victim, the full ETH sweep, and the sponsor's profit. Runs in under a
minute on a warm RPC.

## Profit evidence (fork vs on-chain record)

| Check | On-chain record (mainnet) | Fork replay |
|---|---:|---:|
| Receipt | status=1, block 26186935 | status=1, identical hash |
| Victim code after | `0xef01000366b55f…60d1` | identical |
| Victim ETH | 9.123657838802131 → 0 | identical |
| Sponsor ETH delta | ~9.1231 net of gas (matches ExVul's reported figure) | +9.123097566532401097 |
| Sponsor TAPEETH after | 169,271,471 (1.69271471) | 169,268,788 |

## Known divergences

- **Sponsor TAPEETH drifts slightly run-to-run**: 169,271,471 on
  mainnet at the attack block, 169,268,788 and 169,261,635 across two
  fork replays (≤0.006%). The transfer log moves the full amount on
  every chain; the balance difference comes from TAPEETH's rebase-like
  balance mechanics interacting with fork block timestamps (automined
  at wall-clock time vs the historical timestamp). The gate threshold
  (≥ 169,200,000) accounts for it.
- **Sponsor ETH delta varies by dust** (~31 wei across runs) — the
  sponsor pays gas at the fork's current base fee. Well under the gate
  threshold.
- Nothing else diverges: same tx hash, same status, same delegation
  designator, same ETH endpoints (victim 9.123657838802131 → 0).

## Files

- `transactions/00_0x36e0d149….raw` — the single keccak-verified signed
  type-4 transaction
- `transactions.yaml` — actors, kill-chain description, on-chain record
  values, incident context and references
- `fetch-raw-txs.sh` — provenance check: keccak-gated raw fetch
  (publicnode) with RLP-reconstruction fallback (drpc tx objects)
- `reconstruct_raw.py` — deterministic RLP reconstruction of raw txs
  from tx objects, **type 0/1/2/4** (type 4 includes the EIP-7702
  authorization list)
- `target.yaml` — the mainnet-fork target for the campaign

## Why this incident

- **Cleanest possible replay**: a single self-contained transaction,
  no flash loans, no AMM state, no competing-tx noise — pure
  account-layer attack
- **The 2025–2026 headline drainer class**: EIP-7702 delegation
  phishing (Wintermute measured ~79,000 addresses maliciously delegated
  by one operation for 2.88 ETH; academic measurement found ~70% of
  observed delegations malicious)
- **Durable exposure angle**: the delegation survives the theft — the
  replay demonstrates the standing `0xef0100` designator, the artifact
  ExVul warned about

## Provenance

Raw transaction fetched from a public mainnet RPC and verified with
`keccak256(raw) == tx hash`; independently re-derived by RLP
reconstruction from the on-chain tx object (including the
authorization list). Re-run:

```sh
corpus/eip7702-sveneth-2026/fetch-raw-txs.sh
```
