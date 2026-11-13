# BlockTack architecture

## What BlockTack is

A campaign platform for end-to-end adversarial testing of blockchain
systems. Existing tools (Slither, Echidna, Foundry, ...) are point
solutions for one layer; BlockTack maps the whole attack surface,
orchestrates the right tools per layer, executes attack playbooks against
disposable local/forked environments, and correlates findings into
verified kill chains.

## Layers and languages

Go is the platform (orchestration, networking, scanning — I/O-bound).
Rust is the engines (chain execution, simulation — compute-bound).
Python is thin glue to the existing analysis ecosystem.

```
                        ┌─────────────────────────────────┐
                        │      blocktack CLI (Go)         │
                        │  matrix · recon · scan ·        │
                        │  campaign · report              │
                        └───────┬─────────────────────────┘
                                │
              ┌─────────────────┼──────────────────┐
              ▼                 ▼                  ▼
     ┌────────────────┐ ┌───────────────┐ ┌────────────────┐
     │ recon (Go)     │ │ playbook      │ │ report (Go)    │
     │ L0/L1 probing  │ │ runner (Go)   │ │ markdown/SARIF │
     └────────────────┘ └───┬───────┬───┘ └────────────────┘
                          │       │
        exec + SARIF/JSON │       │ exec + JSON findings
              ┌───────────▼─┐   ┌─▼──────────────────────┐
              │ adapters/   │   │ engine-evm/ (Rust)     │
              │ (Python)    │   │ revm/alloy simulation  │
              │ slither ... │   │ oracle skew, PnL, ...  │
              └─────────────┘   └────────────────────────┘
                          ▲               ▲
                          │   executed against
                ┌─────────┴───────────────┴────┐
                │ local / forked environment  │
                │ (anvil, kurtosis testnets)  │
                └─────────────────────────────┘
```

## Data contracts

Everything crossing a language or process boundary is JSON:

- **Target** (`examples/targets/*.yaml`) — the system under assessment:
  chain, endpoints, contracts, components, and the mandatory
  authorization block. Serialized to JSON for adapters and engines.
- **Finding** (Go `core.Finding`) — the single currency every component
  produces: severity, confidence, taxonomy layer + weakness ID,
  evidence, PoC, source. Interchanged as JSON or SARIF 2.1.0.
- **Playbook** (`playbooks/**/*.yaml`) — a declarative attack campaign:
  ordered steps of type `engine`, `adapter`, `shell`, or `manual`.
- **Job** (engine stdin) — `{"action", "options", "target"}`; the engine
  writes a JSON findings array to stdout.

## Guardrails

Authorization is not optional. The runner refuses targets without an
unexpired `authorization` block, and safe mode (the default) restricts
contactable endpoints to loopback or explicitly authorized hosts. See
docs/authorization.md.

## Extension points

- **New analysis tool** → drop a Python script in `adapters/` following
  `btadapter.py`, register it in `internal/adapter/adapter.go`.
- **New chain engine** → new Rust binary (e.g. `engine-solana/`) speaking
  the job/findings contract; add a playbook that references it.
- **New attack class** → new playbook YAML + taxonomy weakness IDs.
