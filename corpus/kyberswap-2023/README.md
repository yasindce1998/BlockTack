# KyberSwap Elastic incident (2023-11-22, ~$47M multi-chain) — mainnet replay

The KyberSwap Elastic exploit abused a concentrated-liquidity tick
rounding bug (double-counted liquidity when a price range boundary was
crossed twice), draining pools across many chains for ~$47M. This
corpus entry replays the **Ethereum mainnet component (~$7.5M at the
time)**: a self-contained 4-transaction sequence from a single EOA —
contract deployment followed by three attack transactions hitting a
dozen pools — executed in about four minutes on November 22, 2023.

## How the replay works

The four signed mainnet transactions are vendored in `transactions/`.
A local anvil fork starts at block **18630389** — the attacker EOA's
nonces 0-6 (funding/bridging) are already spent, so the deployment
(nonce 7) and attacks (nonces 8-10) re-execute deterministically.

Validated outcome (zero divergence from mainnet):

- all 4 transactions succeed with identical tx hashes and identical
  gasUsed to the mainnet record
- all **11 profit-token balances** of the profit holder
  ("Exploiter 2") match mainnet **to the wei**:
  3,297.14 WETH · 72,978.53 USDC · 25,440.86 FRAX · 640,340.75 KNC ·
  261,977.31 MEME · 192,194.35 ELK · 17.18 MONA · 13.96 frxETH ·
  5.12 wstETH · 2.55 ETHx · 0.0098 HAY

Caveats:
- Only the mainnet component is replayed; the ~$40M on
  Arbitrum/OP/Polygon/Base/Avalanche is out of scope (multi-chain
  sandbox support is a roadmap item).
- Unrelated mainnet traffic in the 16-17 blocks between attack
  transactions is not replayed; verification confirmed zero impact.
- `fetch-raw-txs.sh` re-verifies the vendored raw transactions against
  a public RPC (read-only).

## Run

From the repo root (requires foundry; fork RPC defaults to
https://eth.drpc.org — any archive-capable RPC works via FORK_URL):

```sh
bin/blocktack campaign \
  --target corpus/kyberswap-2023/target.yaml \
  --playbook playbooks/evm/kyberswap-incident-replay.yaml
```

Reference: https://rekt.news/kyberswap-rekt/
