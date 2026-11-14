# BlockTack roadmap

## Phase 0 — Taxonomy + data model ✅ (this scaffold)

- [x] Machine-readable weakness taxonomy (L0–L5, `taxonomy/blocktack-matrix.yaml`)
- [x] Target model with mandatory authorization + safe mode
- [x] Finding model with SARIF 2.1.0 interchange
- [x] Known-exploits regression corpus manifest (`corpus/manifest.yaml`)

## Phase 1 — Platform skeleton + EVM MVP ✅

- [x] Go orchestrator CLI: `matrix`, `recon`, `scan`, `campaign`, `report`
- [x] Functional L0/L1 recon (RPC identity + privileged namespace probing)
- [x] Adapter bridge (Python/SARIF) with Slither as the first adapter
- [x] Playbook schema + campaign runner with artifacts
- [x] Rust engine stub proving the job/findings pipeline
- [x] Foundry adapter (forge build/test; passing `test_poc_*` = confirmed finding)
- [ ] Echidna/Medusa adapter (property-based fuzzing)
- [x] Wire a corpus fixture replay end to end (`corpus/fixtures/naive-oracle-vault`)

## Phase 2 — Adversarial execution environment ✅ (Kurtosis orchestration open)

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
- [x] revm integration: `simulate-tx-sequence` executes raw transaction
      sequences entirely in memory against fork state (AlloyDB +
      WrapDatabaseAsync, simulation cfg flags) — validated mainnet-exact
      on the Curve corpus: identical gasUsed per transaction and profit
      exact to the wei, with zero broadcasts; wired as a simulate-first
      step in the Curve playbook before the fork execution
- [ ] Local multi-client testnet orchestration (wrap Kurtosis)
- [x] Corpus goal: reproduce historical incidents end to end —
      **11 exploits reproduced** (2 fixture classes + 6 Damn Vulnerable
      DeFi challenges + 3 historical incidents replayed on mainnet
      forks by raw-transaction rebroadcast: Euler 2023, the original
      Curve/Vyper pETH-pool drain, and the KyberSwap mainnet
      component). Next incidents: Ronin/Wormhole (require non-EVM
      tooling), KyberSwap's L2 portions (require multi-chain
      sandboxes).

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
- [x] devp2p eclipse execution (`p2p-eclipse` builtin module +
      `playbooks/evm/p2p-eclipse.yaml`): a geth swarm (10 nodes, shared
      PoS genesis) fills all of a victim geth's inbound peer slots;
      admin_peers concentration verifies the eclipse state — critical
      confirmed finding (BTV-L1-002)
- [ ] Timejacking / clock-skew modules
- [x] Client CVE database populated: 18 web-verified entries across
      geth (7), Nethermind (2), Besu (6), Erigon (4) — each checked
      against official GitHub security advisories, release notes, or
      the vendor postmortem, with references and range-bounding caveats
      documented in `internal/nodeaudit/nodecves.yaml`

## Phase 4 — L3/L4 cross-chain and off-chain

- [x] Oracle freshness auditing: `oracle-staleness` engine action calls
      `latestRoundData()` via eth_call and compares `updatedAt` against
      the block timestamp — stale and zero-answer feeds are findings
      (BTV-L4-001); replayable via `playbooks/evm/stale-oracle.yaml`
- [x] Off-chain web attack surface: `web-audit` module (plaintext HTTP,
      missing hardening headers, directory listings, committed `.env`/
      `.git`/pprof/GraphQL exposure) against api/indexer/frontend
      endpoints (BTV-L4-002/003); replayable via
      `playbooks/evm/off-chain-attack-surface.yaml`
- [ ] Bridge model checkers (signature verification, replay domains)
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
- [x] Structured engagement reports: `blocktack report --engagement`
      renders a client-ready deliverable — scope & authorization
      statement, executive summary, kill chains, taxonomy-enriched
      findings with per-weakness remediation guidance (all 52 weaknesses
      carry remediation data), remediation summary table, methodology
      appendix

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

## Phase 7 — AI-readiness (in progress)

AI orchestration lives OUTSIDE BlockTack: the companion project
**RedHands** (MCP server for authorized security assessments) will wrap
the BlockTack binary and supply the intelligence. BlockTack's job is to
become a deterministic, machine-drivable engine — structured I/O,
introspectable capabilities, zero interactive assumptions. AI-assisted
planning stays out of BlockTack by design; RedHands owns the agentic
layer while BlockTack owns execution + guardrails.

- [x] Integration spec (research agent analyzing RedHands' tool layer:
      tool definition shapes, external-binary wrapping conventions,
      chaining hand-offs, long-running tool handling, annotations for
      guardrail mapping) — preserved at `docs/redhands-integration.md`
      with the full 11-tool table and risk register. Architecture
      decision: **RedHands-side wrapper toolset** invoking `bin/blocktack`
      (per-tool Go wrappers modeled on the aegis toolset), campaigns
      driven via BackgroundManager start/status/results
- [x] `--json` output: `matrix --json`, `--emit findings-json` on
      recon/scan/node-audit (default sarif preserved byte-for-byte);
      taxonomy structs gained JSON tags
- [x] `capabilities` introspection command: commands, engines (probed on
      disk), adapters, nodeaudit modules, taxonomy summary
- [x] Campaign decomposition ready: `campaign --progress-json` emits
      JSON-lines events (started/step_started/step_finished/killchain/
      finished) on stdout, and a crash-resilient `status.json` is
      atomically rewritten after every step — killed campaigns leave
      machine-readable state behind
- [x] `validate-target` dry command: target YAML + authorization-block
      validation as a JSON verdict, zero endpoint contact
- [x] Guardrail-to-caller mapping: refusals are typed
      (`core.GuardrailError`, stable codes: missing_authorization,
      missing_expiry, expired_authorization, unsafe_endpoint), the CLI
      reserves **exit code 3** for them, and `BLOCKTACK_JSON_ERRORS=1`
      emits structured error objects on stderr. `--unsafe` is never a
      parameter in any of the new surfaces; safe-mode enforcement stays
      in BlockTack code (`ValidateSafeMode`, double-checked by the
      campaign runner)

## Phase 8 — Backlog (2025–2026 attack surface, agreed sequencing)

Sequenced per signal-vs-risk discussion: 7702 + v4 hooks first (highest
2025-2026 signal, lowest engineering risk given the revm work), then
symbolic execution (the categorical differentiator).

- [ ] EIP-7702 delegation abuse: revm already parses
      `authorization_list`; replay real 7702 wallet-drainer sequences
      on forks via `simulate-tx-sequence` — most current incident class
- [ ] Uniswap v4 hooks: hook-simulation action (eth_call state
      overrides + revm multi-tx) replaying real hook exploits;
      per-hook attack surface on singleton pools
- [ ] Symbolic execution on revm: extend `simulate-tx-sequence` from
      replay to counterfactual exploration — path/constraint solving
      over storage to find inputs hitting a profit condition (turns the
      corpus from regression suite into discovery engine)
- [ ] ERC-4337 bundler/paymaster simulation: policy griefing, gas-token
      arbitrage in bundles, validateUserOp DoS
- [ ] L1↔L2 cross-domain MEV replay on the two-chain fork harness
      (same-block arb, sequencer timing, forced inclusion)
- [ ] Restaking/AVS economic attacks (EigenLayer-style slashing
      conditions, operator-set capture) — L5 deepening
- [ ] Blob-era mechanics: 4844 blob txs in replays, EIP-7825/8037
      behaviors, blob-pool mempool analysis
- [ ] Intents/private-orderflow layer: solver-competition simulation,
      settlement replays, malicious-solver backruns
- [ ] Real-time shadow node: follower geth/erigon streaming live
      mempool through mempool-analysis (read-only continuous
      surveillance)
- [ ] L3 bridge light-client checkers: replay domains, signature
      malleability in verifiers, SNARK soundness assumptions
      (Wormhole/Ronin class)
- [ ] RIP-7212 passkey wallets (secp256r1): precompile/signature
      malleability module for WebAuthn smart accounts
