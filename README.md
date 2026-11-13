# BlockTack

**End-to-end adversary simulation for blockchain systems.**

BlockTack is a campaign platform for offensive security assessment of
whole blockchain systems — not just smart contracts. It maps the full
attack surface, orchestrates the best tooling per layer, executes attack
playbooks against disposable local/forked environments, and turns results
into verified findings.

> **Status:** Phase 0/1 scaffold — data model, guardrails, CLI, recon,
> adapter bridge, playbook runner, and engine pipeline are wired; the
> EVM engine is a stub pending revm/alloy integration. See
> [docs/roadmap.md](docs/roadmap.md).

## The attack surface

| Layer | Scope                                                        |
|-------|--------------------------------------------------------------|
| L0    | Infrastructure — RPC exposure, node config, secrets           |
| L1    | Node & consensus — clients, p2p, mempool, validators          |
| L2    | Contracts & programs — EVM, Solana BPF, Move, CosmWasm        |
| L3    | Cross-chain — bridges, relayers, light clients                |
| L4    | Off-chain — oracles, indexers, frontends, custodians, keys    |
| L5    | Economic & governance — incentive design, governance, MEV     |

Browse the machine-readable weakness taxonomy with `blocktack matrix`.

## Architecture

Go orchestrates, Rust computes, Python glues to the existing analysis
ecosystem (Slither et al.). Everything crosses process boundaries as JSON
or SARIF. See [docs/architecture.md](docs/architecture.md).

```
blocktack CLI (Go) ── recon · scan · campaign · report
      ├── adapters/ (Python)      slither → findings
      ├── engine-evm/ (Rust)      simulation & exploits → findings
      └── playbooks/ (YAML)       declarative attack campaigns
```

## Quickstart

```sh
make build            # Go CLI + Rust engine

bin/blocktack matrix  # browse the weakness taxonomy

# Recon against a local anvil node (safe by default):
anvil &
bin/blocktack recon --target examples/targets/local-anvil.yaml --out /tmp/findings.json

# Run an attack playbook (campaign output lands in runs/campaigns/):
bin/blocktack campaign \
  --target examples/targets/mainnet-fork.yaml \
  --playbook playbooks/evm/oracle-manipulation.yaml

# Merge findings into a report:
bin/blocktack report --findings /tmp/findings.json --out report.md
```

## Guardrails

Authorization is not optional: every target YAML must declare an
authorization block (who, scope, expiry), and safe mode — the default —
restricts endpoints to loopback or explicitly authorized hosts. See
[docs/authorization.md](docs/authorization.md). Only test systems you are
authorized to test.

## Repository layout

```
cmd/blocktack/       CLI entrypoint (Go)
internal/core/       target, finding, taxonomy models (Go)
internal/recon/      L0/L1 endpoint probing (Go)
internal/adapter/    adapter bridge to Python/SARIF tools (Go)
internal/playbook/   playbook schema + campaign runner (Go)
internal/report/     report rendering (Go)
adapters/            Python adapters (Slither, ...)
engine-evm/          EVM attack engine (Rust)
taxonomy/            the weakness matrix (YAML)
playbooks/           attack playbooks (YAML)
corpus/              known-exploits regression set
examples/targets/    example target definitions
docs/                architecture, roadmap, authorization
```

## Proving ground

`corpus/manifest.yaml` tracks real historical exploits (Ronin, Wormhole,
Euler, Mango, Bybit, ...) as regression targets. The platform's goal
metric: how many can a campaign replay end to end on a forked chain.

## License

See [LICENSE](LICENSE).
