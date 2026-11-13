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
- [ ] Foundry adapter (forge test / invariant harness auto-generation)
- [ ] Echidna/Medusa adapter (property-based fuzzing)
- [ ] Wire Damn Vulnerable DeFi as the first corpus replay

## Phase 2 — Adversarial execution environment

- [ ] revm/alloy integration in `engine-evm`: fork state manipulation,
      block-level simulation, state overrides
- [ ] Implement real `map-oracles`, `oracle-skew`, `verify-pnl` actions
- [ ] Local multi-client testnet orchestration (wrap Kurtosis)
- [ ] Attack verification: every critical finding carries a replayable PoC
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
