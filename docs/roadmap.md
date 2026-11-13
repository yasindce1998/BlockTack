# BlockTack roadmap

## Phase 0 — Taxonomy + data model ✅ (this scaffold)

- [x] Machine-readable weakness taxonomy (L0–L5, `taxonomy/blocktack-matrix.yaml`)
- [x] Target model with mandatory authorization + safe mode
- [x] Finding model with SARIF 2.1.0 interchange
- [x] Known-exploits regression corpus manifest (`corpus/manifest.yaml`)

## Phase 1 — Platform skeleton + EVM MVP (current)

- [x] Go orchestrator CLI: `matrix`, `recon`, `scan`, `campaign`, `report`
- [x] Functional L0/L1 recon (RPC identity + privileged namespace probing)
- [x] Adapter bridge (Python/SARIF) with Slither as the first adapter
- [x] Playbook schema + campaign runner with artifacts
- [x] Rust engine stub proving the job/findings pipeline
- [x] Foundry adapter (forge build/test; passing `test_poc_*` = confirmed finding)
- [ ] Echidna/Medusa adapter (property-based fuzzing)
- [x] Wire a corpus fixture replay end to end (`corpus/fixtures/naive-oracle-vault`)

## Phase 2 — Adversarial execution environment (in progress)

- [x] alloy integration in `engine-evm` with three real actions:
      `fingerprint` (chain identity), `map-oracles` (bytecode selector
      scan for oracle dependencies, keccak-verified selectors),
      `verify-pnl` (balance-delta profit verification)
- [x] First end-to-end campaign: boot anvil → deploy fixture → map
      oracles from bytecode → execute price-skew attack on-chain via
      cast → verify attacker profit → cross-check with forge PoC
      (`playbooks/evm/naive-oracle-vault.yaml`)
- [ ] revm integration: state overrides and block-level simulation for
      attacks that must not touch even a local chain
- [ ] Local multi-client testnet orchestration (wrap Kurtosis)
- [ ] Corpus goal: reproduce 5 historical exploits end to end

## Phase 3 — L0/L1 node and consensus attacks

- [ ] Client version → known CVE cross-referencing
- [ ] RPC fuzzing harnesses (AFL++/cargo-fuzz against handlers)
- [ ] devp2p/libp2p harness: eclipse and sybil test modules
- [ ] Mempool analysis and sniping playbooks

## Phase 4 — L3/L4 cross-chain and off-chain

- [ ] Bridge model checkers (signature verification, replay domains)
- [ ] Oracle manipulation campaigns beyond EVM (Pyth/Chainlink feeds)
- [ ] Indexer/API attack surface (embed nuclei engine)
- [ ] Frontend/key-management assessment modules

## Phase 5 — Correlation + reporting

- [ ] Attack-graph engine: compose multi-layer findings into kill chains
- [ ] Crypto-adapted scoring (financial blast radius, not just CVSS)
- [ ] Engagement reports with PoC replay and remediation mapping

## Phase 6 — Non-EVM expansion

- [ ] `engine-solana` (Trident integration, BPF analysis)
- [ ] Move chains (Move Prover integration)
- [ ] CosmWasm + Cosmos SDK state-machine fuzzing (Go)
- [ ] Permissioned chains (Besu, Fabric)
