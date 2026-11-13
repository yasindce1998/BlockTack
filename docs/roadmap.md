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
- [x] Corpus goal: reproduce historical incidents end to end —
      **9 exploits reproduced** (2 fixture classes + 6 Damn Vulnerable
      DeFi challenges + the Euler 2023 incident replayed on a mainnet
      fork by raw-transaction rebroadcast). Next incidents: Ronin
      (requires non-EVM tooling), Wormhole (Solana), Curve/Vyper 2023.

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

- [x] Oracle freshness auditing: `oracle-staleness` engine action calls
      `latestRoundData()` via eth_call and compares `updatedAt` against
      the block timestamp — stale and zero-answer feeds are findings
      (BTV-L4-001); replayable via `playbooks/evm/stale-oracle.yaml`
- [x] Off-chain web attack surface: `web-audit` module (plaintext HTTP,
      missing hardening headers, directory listings, committed `.env`/
      `.git`/pprof/GraphQL exposure) against api/indexer/frontend
      endpoints (BTV-L4-002/003); replayable via
      `playbooks/evm/off-chain-attack-surface.yaml`- [ ] Bridge model checkers (signature verification, replay domains)
- [ ] Relayer/light-client misconfiguration modules
- [ ] Cross-chain message replay campaigns on multi-chain sandboxes

## Phase 5 — Correlation + reporting

- [x] Kill-chain engine (`internal/correlate`): composes multi-layer
      findings into single compromise narratives — oracle manipulation,
      reentrancy drain, node surveillance/eclipse-recon, and off-chain
      credential exposure chains (the Multichain/Radiant/Bybit shape)
- [x] Crypto-adapted impact: verified financial blast radius parsed
      from on-chain balance deltas (reported in ETH + wei)
- [x] Campaigns auto-correlate: composite findings flow into
      findings.json/reports; killchains.json written per campaign
- [ ] Graph-based cross-campaign correlation (same target over time)
- [ ] Structured engagement report templates (exec summary, remediation
      mapping back to taxonomy)

## Phase 6 — Non-EVM expansion

- [x] `engine-solana` (Rust): speaks the same job/findings contract as
      engine-evm via Solana JSON-RPC — `fingerprint` (getVersion,
      getEpochInfo) and `balance` (getBalance, lamports) actions,
      verified live against public devnet; smoke playbook
      `playbooks/solana/devnet-fingerprint.yaml`
- [x] Engine resolution generalized: binaries resolve to
      `engine-<chain>/target/release/` by name
- [ ] Solana program analysis (Trident integration, BPF bytecode)
- [ ] Move chains (Move Prover integration)
- [ ] CosmWasm + Cosmos SDK state-machine fuzzing (Go)
- [ ] Permissioned chains (Besu, Fabric)
