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

- [x] alloy integration in `engine-evm` with four real actions:
      `fingerprint` (chain identity), `map-oracles` (bytecode selector
      scan for oracle dependencies, keccak-verified selectors),
      `verify-pnl` (balance-delta profit verification), `simulate-call`
      (eth_call with storage overrides + value — attack premises
      verified without broadcasting transactions)
- [x] First end-to-end campaign: boot anvil → deploy fixture → map
      oracles from bytecode → simulate the attack → execute price-skew
      on-chain via cast → verify attacker profit → cross-check with
      forge PoC (`playbooks/evm/naive-oracle-vault.yaml`)
- [x] Second end-to-end campaign: reentrancy drain fully simulated via
      eth_call (reentrancy executes in simulation) then executed
      on-chain (`playbooks/evm/reentrant-vault.yaml`)
- [ ] revm integration: full block-level simulation beyond eth_call
      state overrides (multi-transaction scenarios)
- [ ] Local multi-client testnet orchestration (wrap Kurtosis)
- [ ] Corpus goal: reproduce 5 historical exploits end to end (2
      fixture classes done)

## Phase 3 — L0/L1 node and consensus attacks

- [x] Client version → known-CVE cross-referencing (`cve-check` builtin
      module; version parsing handles geth/nethermind/besu/anvil
      formats; seed vulnerability DB in `internal/nodeaudit/nodecves.yaml`)
- [x] Malformed-RPC-input fuzzing with post-battery health checks —
      an unresponsive node after the battery is a critical DoS finding
      (`rpc-fuzz`)
- [x] Mempool exposure and front-running surface analysis
      (`mempool-analysis`, BTV-L1-009/BTV-L5-004)
- [x] Peer-topology exposure and eclipse-susceptibility heuristics
      (`peer-analysis`, BTV-L0-002/BTV-L1-002)
- [x] Playbook `playbooks/evm/node-attack-surface.yaml` and CLI command
      `blocktack node-audit`
- [ ] devp2p/libp2p protocol-level harness (eclipse/sybil execution,
      not just topology heuristics)
- [ ] Timejacking / clock-skew modules
- [ ] Full client CVE database (the seed ships one verified entry)

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
