# Curve/Vyper reentrancy incident (2023-07-30) — historical replay

On July 30, 2023, an attacker exploited broken `nonreentrant` locks in
Vyper 0.2.15/0.2.16/0.3.0 to drain Curve stablecoin pools compiled with
those versions (~$70M across pools and copycats). This corpus entry
replays the **original attacker's complete, self-contained sequence
against the JPEG'd pETH/ETH pool (~$11M, the incident's first drain)**:
an 80k WETH Balancer flash loan funds a reentrancy drain of the broken
pool, netting **6,106.751307562450092427 WETH** — swept to the attacker
EOA in the final transaction.

## How the replay works

The three signed mainnet transactions are vendored in `transactions/`.
A local anvil fork starts at block **17806055** — attacker EOA at nonce
167 (matching the first replayed tx), attack contract already deployed —
and re-publishing the historical transactions reproduces the drain
deterministically. On mainnet the exploit landed at block 17806056
index 0; the replay is positionally exact.

Validated outcome (both validation runs identical):

- all 3 transactions succeed; gasUsed matches mainnet exactly
  (1,693,119 / 38,647 / 53,489)
- attacker profit: 6,106.751307562450092427 WETH — **exact match to the
  wei** against the mainnet record
- pool LP totalSupply after the attack (942.555844397021387324) — exact
  match; pool ETH drops 6,185.56 → 77.90

Caveats:
- Other attackers (msETH, alETH, CRV/ETH pools, the c0ffeebabe MEV bot)
  were dropped: their setup (funding + contract deployment) post-dates
  the fork block, while the pETH sequence is fully self-contained.
- Pool-side values at mainnet block boundaries differ slightly from the
  fork because MEV bots arbitraged the broken pool in the same block
  after the exploit; attacker-side values match exactly regardless.
- `fetch-raw-txs.sh` re-verifies the vendored raw transactions against a
  public RPC (read-only).

## Run

From the repo root (requires foundry; fork RPC defaults to
https://eth.drpc.org — any archive-capable RPC works via FORK_URL):

```sh
bin/blocktack campaign \
  --target corpus/curve-vyper-2023/target.yaml \
  --playbook playbooks/evm/curve-vyper-incident-replay.yaml
```

Reference: https://rekt.news/curve-vyper-rekt/
