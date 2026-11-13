# Euler Finance incident (2023-03-13, ~$197M) — historical replay

BlockTack's first **historical incident** corpus entry. The attacker
exploited Euler's `donateToReserves` combined with self-liquidation:
flash-loaned capital was deposited, donated to reserves to make the
account insolvent, then self-liquidated at a discount, extracting value
from the protocol's socialized-debt accounting. Six attacks across
several assets, ~43M DAI + ~97k ETH total.

## How the replay works

The attacker's 15 signed mainnet transactions (contract deploys, six
attacks, profit sweeps) are vendored in `transactions/` in on-chain
order. A local anvil fork starts at block **16817992** — after this
block both attacker EOAs are at nonce 0 and nothing has executed — so
re-broadcasting the historical signed transactions reproduces the
incident deterministically: same signatures, same nonces, same state.

Validated outcome vs mainnet at block 16818086:

| Holder | Asset | Replay result | Mainnet |
|---|---|---|---|
| attack contract 1 | DAI | 8,877,507.35 | exact match |
| attack contract 2 | DAI | 34,186,133 | within 0.1% |
| attack contract 2 | ETH | 88,813 | within 0.1% |
| attacker EOA 2 | ETH | 8,081 | within 0.1% |

Caveats:
- Attacks 2 and 5 take a no-op path on the fork (non-attacker
  transactions from the original blocks are not replayed, so liquidity
  and rates drift); they do not revert and the end state still matches.
- The fork block is load-bearing: forking any later skips the contract
  deployments and breaks the final attack.
- `fetch-raw-txs.sh` re-verifies the vendored raw transactions against
  a public RPC (read-only).

## Run

From the repo root (requires foundry; the fork RPC defaults to
https://eth.drpc.org — any archive-capable RPC works via FORK_URL):

```sh
bin/blocktack campaign \
  --target corpus/euler-2023/target.yaml \
  --playbook playbooks/evm/euler-incident-replay.yaml
```

Reference: https://rekt.news/euler-rekt/
