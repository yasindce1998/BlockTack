# BlockTack

**End-to-end adversary simulation for blockchain systems.**

[![CI](https://github.com/yasindce1998/BlockTack/actions/workflows/ci.yml/badge.svg)](https://github.com/yasindce1998/BlockTack/actions/workflows/ci.yml)

BlockTack maps a blockchain system's full attack surface, orchestrates the
right tooling per layer, **executes attacks** — in pure simulation or
against disposable forks — verifies the profit, and composes everything
into kill chains and engagement-grade reports.

It is not a scanner. It is a campaign platform: recon → threat-model-driven
attack execution → verified impact → client-ready report.

> **Proof, not claims:** the regression corpus reproduces **11 exploits**,
> including three historical incidents — Euler 2023 (~$197M), the original
> Curve/Vyper drain, and KyberSwap 2023 — replayed on mainnet forks by
> re-broadcasting the attackers' own signed transactions, with profits
> verified against the on-chain record **to the wei**.

## The attack surface

Every finding, playbook, and report is classified against a
machine-readable taxonomy of 52 weakness classes across six layers
(`blocktack matrix` to browse):

| Layer | Scope | BlockTack capabilities |
|---|---|---|
| **L0** Infrastructure | RPC exposure, node config, secrets | recon, RPC fuzzing (DoS detection), web audit, CVE cross-reference |
| **L1** Node & consensus | clients, p2p, mempool, validators | fingerprinting, mempool surveillance, peer-topology analysis, **eclipse execution** (geth swarm) |
| **L2** Contracts & programs | EVM, Solana BPF, Move, CosmWasm | bytecode oracle mapping, static adapters (Slither), forge PoC execution (Foundry), **revm multi-transaction simulation**, eth_call state overrides |
| **L3** Cross-chain | bridges, relayers, light clients | replay-domain and proof-verification checks *(roadmap)* |
| **L4** Off-chain | oracles, indexers, frontends, keys | oracle staleness/zero-answer detection, web-root secret exposure, headers, listings |
| **L5** Economic & governance | incentive design, MEV | balance-delta profit verification (ETH and ERC-20), kill-chain composition with financial blast radius |

## Three tiers of realness

BlockTack was built for professional use, so it is explicit about what is
synthetic, what is real-but-sandboxed, and what runs against live approved
systems:

1. **Synthetic** — corpus fixtures and wargame challenges (Damn Vulnerable
   DeFi). Regression tests for the tool itself.
2. **Real data, sandboxed execution** — historical incidents replayed on
   local forks of *real* mainnet state, executing the *real* attackers'
   *real* signed transactions. Nothing ever reaches mainnet. The
   `simulate-tx-sequence` engine action goes further: entire attack
   sequences run **in revm, in memory** — zero broadcasts, not even to a
   local chain.
3. **Live, against approved systems** — read-only probing (`recon`,
   `node-audit`, `map-oracles`, `oracle-staleness`), web audits, and
   `simulate-call` (eth_call with state overrides: ask "would this borrow
   succeed if the oracle reported a skewed price?" against **live**
   contracts with zero footprint). Point a target at your own
   infrastructure with a proper authorization block.

## Architecture

Go orchestrates, Rust computes, Python glues to the existing analysis
ecosystem. Everything crosses process boundaries as JSON or SARIF.
Chain-specific engines live in `engine-<chain>/` and speak one job/findings
contract — new chains are drop-in.

```
blocktack CLI (Go) ── matrix · recon · scan · node-audit · campaign · report
      │
      ├── internal/ (Go modules)
      │     recon · nodeaudit (cve/fuzz/mempool/peers/web) · p2pattack
      │     playbook runner (shell/engine/adapter/builtin/manual steps)
      │     correlate (kill chains + financial blast radius)
      │     report (severity dump + engagement-grade renderer)
      │
      ├── adapters/ (Python)          Slither · Foundry
      │                               passing test_poc_* = confirmed finding
      │
      ├── engine-evm/ (Rust, alloy + revm)
      │     fingerprint · map-oracles · verify-pnl · oracle-staleness
      │     simulate-call (state overrides) · erc20-balance
      │     simulate-tx-sequence (in-memory multi-tx, mainnet-exact)
      │
      └── engine-solana/ (Rust)       fingerprint · balance (JSON-RPC)

executed against: anvil forks · foundry EVMs · geth swarms · live RPCs (read-only)
```

## Quickstart

Requires [Go](https://go.dev) 1.27+, Rust, and [Foundry](https://getfoundry.sh)
(`anvil`, `cast`, `forge`). [Geth](https://geth.ethereum.org) ≥1.14 is
optional (only for the p2p-eclipse campaign).

```sh
make build            # Go CLI + both Rust engines
make test             # full test suite

bin/blocktack matrix  # browse the 52-weakness taxonomy
```

Run a campaign (from the repo root):

```sh
# Full-stack oracle exploit: deploy → map oracles from bytecode →
# simulate the skewed-price borrow (no broadcast) → execute on-chain →
# verify profit → forge PoC → kill chain + financial impact:
bin/blocktack campaign \
  --target corpus/fixtures/naive-oracle-vault/target.yaml \
  --playbook playbooks/evm/naive-oracle-vault.yaml

# Reentrancy drain, fully simulated first:
bin/blocktack campaign \
  --target corpus/fixtures/reentrant-vault/target.yaml \
  --playbook playbooks/evm/reentrant-vault.yaml

# Damn Vulnerable DeFi wargame corpus (6 challenges):
bin/blocktack campaign \
  --target corpus/damn-vulnerable-defi/target.yaml \
  --playbook playbooks/evm/damn-vulnerable-defi.yaml

# Historical incidents (archive-capable fork RPC; FORK_URL to override):
bin/blocktack campaign \
  --target corpus/euler-2023/target.yaml \
  --playbook playbooks/evm/euler-incident-replay.yaml
bin/blocktack campaign \
  --target corpus/curve-vyper-2023/target.yaml \
  --playbook playbooks/evm/curve-vyper-incident-replay.yaml      # + revm simulation
bin/blocktack campaign \
  --target corpus/kyberswap-2023/target.yaml \
  --playbook playbooks/evm/kyberswap-incident-replay.yaml

# Node layer (CVEs, RPC fuzzing, mempool, peer topology):
bin/blocktack node-audit --target examples/targets/local-anvil.yaml

# Off-chain web audit · eclipse execution · Solana recon:
bin/blocktack node-audit --target corpus/fixtures/off-chain-api/target.yaml --module web-audit
bin/blocktack campaign --target corpus/fixtures/p2p-eclipse/target.yaml \
  --playbook playbooks/evm/p2p-eclipse.yaml
bin/blocktack campaign --target examples/targets/solana-devnet.yaml \
  --playbook playbooks/solana/devnet-fingerprint.yaml

# Engagement-grade report from any campaign output:
bin/blocktack report --findings runs/campaigns/<run>/findings.json \
  --target <target.yaml> --engagement --out report.md
```

## What a campaign looks like

```
$ bin/blocktack campaign --target corpus/fixtures/naive-oracle-vault/target.yaml \
    --playbook playbooks/evm/naive-oracle-vault.yaml

kill chain: [critical] End-to-end oracle manipulation kill chain
  stage: Weakness identified: Oracle dependency: latestAnswer() (BTV-L2-003)
  stage: Exploit premise confirmed by simulation (no transaction broadcast)
  stage: Exploit executed on-chain and profit verified
  financial impact: 14.999936 ETH (14999935592435371203 wei)
campaign finished: 6 findings
```

## The proving ground

`corpus/manifest.yaml` tracks real exploits as regression targets with
`pending → detected → reproduced` statuses. Current scoreboard:

| Class | Count | Examples |
|---|---|---|
| Synthetic fixture classes | 2 | oracle manipulation, reentrancy (each: simulated → executed → PoC) |
| Damn Vulnerable DeFi | 6 | naive-receiver (sender forgery), the-rewarder (claim replay ×1700), free-rider, … |
| Historical incidents | 3 | Euler 2023 · Curve/Vyper 2023 · KyberSwap 2023 — profits to the wei |

The Curve incident is proven three ways: **revm in-memory → anvil fork
broadcast → on-chain record**, with identical gasUsed and balances at every
stage. Vendored attacker transactions carry provenance scripts that
re-verify the bytes against public RPCs.

## Guardrails

Authorization is not optional. Every target must declare an
authorization block (who, scope, expiry); safe mode (the default)
restricts contactable endpoints to loopback or explicitly allow-listed
hosts; going beyond requires an explicit `--unsafe`. Campaigns are fully
logged with per-step artifacts. The replay workflows broadcast only to
local forks. See [docs/authorization.md](docs/authorization.md) — and only
test systems you are authorized to test.

## Repository layout

```
cmd/blocktack/        CLI (Go)
internal/core/        target, finding, taxonomy models
internal/recon/       L0/L1 endpoint probing
internal/nodeaudit/   cve-check · rpc-fuzz · mempool · peers · web-audit
internal/p2pattack/   eclipse-state verification
internal/playbook/    campaign runner (all step types)
internal/correlate/   kill-chain composition, financial blast radius
internal/report/      severity report + engagement renderer
internal/webaudit/    off-chain web exposure checks
adapters/             Python adapters (Slither, Foundry)
engine-evm/           EVM engine (Rust: alloy + revm)
engine-solana/        Solana engine (Rust)
taxonomy/             52-weakness attack matrix (with remediation)
playbooks/            declarative attack campaigns (11 EVM + 1 Solana)
corpus/               exploit regression corpus + vendored incidents
examples/targets/     target definitions
docs/                 architecture · roadmap · authorization
```

## Status & roadmap

The platform is feature-complete across L0/L1/L2/L4/L5 with three
historical incidents reproduced. Open items — non-EVM incident replays
(Ronin, Wormhole), L2/L3 multi-chain sandboxes, bridge model checkers,
Move/CosmWasm engines, timejacking — are tracked in
[docs/roadmap.md](docs/roadmap.md).

## License

See [LICENSE](LICENSE).
