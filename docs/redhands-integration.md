# BlockTack ↔ RedHands Integration Specification

**Status:** research deliverable (no repos modified)
**Date:** 2026-11-14
**Scope:** make BlockTack (`/home/yasin/BlockTack`, Go CLI + Rust engines) machine-drivable from RedHands (`/home/yasin/RedHands`, Go MCP server). AI planning stays in RedHands; BlockTack stays deterministic.

---

## 0. Executive summary

- **Recommended architecture: (a) RedHands-side wrapper toolset.** Add `tools/blocktack/` to RedHands following the exact pattern used by the existing `aegis`, `telecom`, and `barzakh` toolsets (each of which already wraps an external security binary platform, including managed background daemons for long-running components). This requires ~6 files in RedHands and ~5 small additive changes in BlockTack.
- **Long-running campaigns are solved machinery, not a new problem:** RedHands' `BackgroundManager` (`pkg/executor/background.go`) exists precisely for "defense engine / offense loader daemons that run for minutes" and is already used by three toolsets. BlockTack campaigns map 1:1 onto the `*_start` / `*_status` / `*_results` triad.
- **Critical ergonomic gap found:** the RedHands `Executor` interface (`Run(ctx, binary, args...)`) has **no way to set working directory or environment** for the child process. BlockTack resolves its taxonomy, adapters, and Rust engine binaries relative to `BLOCKTACK_ROOT`/cwd (`internal/core/target.go:183-199`, `internal/playbook/runner.go:290-297`). Either RedHands gains Dir/Env support on the executor, or BlockTack is installed with a tiny absolute-path wrapper. This is the only non-trivial cross-cutting change.
- **Guardrail story is strong and verifiable:** BlockTack refuses unauthorized targets *in code* (`internal/core/target.go:120-141` — `ValidateSafeMode` checks the authorization block, expiry, and loopback/liveTargets confinement) and every command calls it before doing anything. The MCP-facing tools therefore never need to pass `--unsafe`; the tool layer simply does not expose it.
- **No blockchain toolset exists in RedHands today** (294 tools across 36 toolsets; verified `internal/registry/registry.go`). `blocktack` would be toolset #37 and the first Web3 domain.

---

## 1. RedHands integration surface (what the spec must conform to)

### 1.1 Tool definition and registration

- The tool contract is a minimal Go interface: `Name() string`, `Description() string`, `InputSchema() json.RawMessage`, `Execute(ctx, params) (*ToolResult, error)` — `pkg/mcp/tool.go:8-13`.
- Registration goes through `Server.RegisterTool` (`pkg/mcp/server.go:83-96`), which validates the input schema (must be an object; a `$schema` keyword, if present, must be JSON Schema 2020-12 — `server.go:101-119`) and assigns a **conservative default policy** (`server.go:94`): `{NetworkAccess: true, RequiresPrivileges: true, RequiresApproval: true}` (`pkg/mcp/policy.go:17-19`).
- Real policy metadata is set centrally by the reviewed table `internal/registry/policy.go:7-122` (`builtinPolicies()`), wired at `internal/registry/registry.go:512-514`. Comments there state the philosophy: *"Built-in policies are reviewed by capability, not inferred from tool names."*
- `tools/list` publishes, per tool: name, description, inputSchema, an `x-redhands-policy` object (ReadOnly / NetworkAccess / RequiresPrivileges / RequiresApproval / RetrySafe / Cacheable), and MCP `annotations` **derived from policy**, not from the tool itself: `readOnlyHint = policy.ReadOnly`, `destructiveHint = !policy.ReadOnly`, `idempotentHint = policy.RetrySafe`, `openWorldHint = policy.NetworkAccess` (`pkg/mcp/handler.go:162-168`, types at `pkg/mcp/protocol.go:157-170`). **Consequence: an AI client's safety picture is only as good as the policy table — declare each BlockTack tool's policy deliberately (table in §3).**
- Per-toolset registration is gated on `cfg.ToolsetEnabled(name)` and centralized in `internal/registry/registry.go:84-515`. Pattern to copy: the aegis block at `registry.go:361-377` (dependency-free tools directly; daemon lifecycle tools only `if d.ProcMgr != nil`).
- `Deps` (`registry.go:71-82`) already carries `ProcMgr *executor.BackgroundManager` and `Exec executor.Executor` — exactly what the BlockTack toolset needs.

### 1.2 How RedHands wraps external binaries

Both patterns exist; production toolsets use **per-tool Go wrappers**, not the generic path:

1. **Per-tool Go wrappers (the dominant pattern).** Each binary gets a package under `tools/<toolset>/<binary>/` with hand-written tools whose `Execute()` unmarshals JSON params, validates them against an enum/allowlist, builds an argv, and calls `executor.Executor.Run(ctx, binary, args...)`. Example: `tools/scan/nmap/port_scan.go` (constructor `NewPortScan(exec)`, strict `InputSchema`, structured output via `pkg/nmap` parser). ~36 toolsets follow this shape.
2. **Generic JSON plugins (day-zero bridge only).** `pkg/plugin/loader.go:18-24` defines `{name, description, binary, args_template, input_schema}` JSON files dropped in `REDHANDS_PLUGINS_DIR`; `PluginTool.Execute` (`loader.go:36-90`) does Go-template arg substitution and wraps raw stdout/stderr in a fenced code block. Limitations: no annotations control, always `ConservativePolicy` (approval-required) via `RegisterTool`, no output parsing, no background/daemon support, no policy table entry. **Fine for a proof-of-concept; wrong end-state.**

**Conventions a wrapped binary must satisfy** (from `pkg/executor/executor.go`):
- The binary name must be in the allowlist discovered by `internal/binaries/binaries.go` (`Discover()` resolves names on PATH; the name list at `binaries.go:34-64` is the one line to extend with `"blocktack"`). Non-allowlisted → `binary not allowed` error (`executor.go:39-42`).
- Arguments must be free of shell metacharacters — `validateArgs` runs on every call (`executor.go:44-46`; README §Security: "Argument validation — shell metacharacter rejection"). **No `sh -c` strings through the executor; every BlockTack flag must be its own argv element.**
- Bounded execution: per-call timeout `REDHANDS_TIMEOUT` (default 5m, README:785) enforced by the concurrency limiter (`pkg/execution/limiter.go:41-48`) **and** the executor context (`executor.go:48`); output is capped at `REDHANDS_MAX_OUTPUT` (10 MB default, `config.go:81`) across stdout+stderr combined (`executor.go:55-58`); exceeding it aborts with a truncation error (`executor.go:75-77`).
- Exit codes are surfaced but *non-zero exit alone fails the call* (`executor.go:79-81`) — wrappers that want "exit 1 = findings" semantics (like barzakh_scan, README:331) must special-case the `Result.ExitCode`.
- **The executor does not support child cwd/env**: `Run(ctx, binary, args...)` (`executor.go:26-28`) has no Dir or Env parameters and `applySandbox` does not add them. See §4.0 (gap G1).

### 1.3 Tool chaining and data hand-off

- Chained calls run through the same `Server.ExecuteTool` path (`pkg/mcp/server.go:141-171`).
- Hand-off format is **the rendered result text with a fenced JSON block**, extractable by dot-path placeholders: `$prev.text`, `$prev.json.findings.0.severity`, `${step_id.json.hosts.0.ip}` (README:588-604). The convention is explicitly documented in wrapper code: aegis `defense_start` emits a fenced `{"process_id": ..., "pid": ...}` block *so campaign dataflow can reference `${step_id.json.process_id}`* (`tools/aegis/defense_start.go:228-237`).
- Campaign `record` rules can map JSON arrays from a step's output into the target DB (hosts/services/credentials/findings — README:604-627), and steps carry MITRE tags aggregated into `mitre_techniques` (README:629-635). **BlockTack findings are `{id,title,severity,confidence,weakness,source,...}` (SARIF-mapped) — emitting them as a fenced JSON array makes them chainable AND recordable.**
- Modern protocol revision also supports `ToolResult.StructuredContent` (native JSON result object — `pkg/mcp/protocol.go:185-188`), used by `campaign_start` to mirror the `CreateTaskResult` shape (`tools/campaign/start.go:222-224`). New BlockTack tools should emit both fenced JSON (for legacy chaining) and `StructuredContent` where the result is pure data.

### 1.4 Domain/category organization

- Toolsets are Go packages under `tools/` (`tools/ad`, `tools/aegis`, `tools/analysis`, `tools/barzakh`, `tools/c2`, `tools/cloud`, `tools/crack`, `tools/exploit`, `tools/firmware`, `tools/fuzz`, `tools/intelligence`, `tools/kubedagger`, `tools/mobile`, `tools/msf`, `tools/operations`, `tools/recon`, `tools/reporting`, `tools/sbom`, `tools/scan`, `tools/searchsploit`, `tools/social`, `tools/system`, `tools/targetdb`, `tools/telecom`, `tools/tunnel`, `tools/vuln`, `tools/web`, `tools/wireless` — verified listing).
- There is **no blockchain/Web3 toolset today** (grep over registry + tools confirms). The closest analogues — platform-wrapper toolsets that bundle (i) read-only analysis tools, (ii) managed background daemons with start/stop/status, (iii) report/history tools — are `aegis` and `telecom`. BlockTack fits that mold exactly; propose `tools/blocktack/`, toolset id `blocktack`, tool prefix `blocktack_`.
- Toolset activation: `REDHANDS_TOOLSETS` comma-list, default all (README:784, 853-872).

### 1.5 Rate limiting, caching, audit vs. long-running tools

Middleware order is fixed at `internal/app/middleware.go:18-55`: **audit → auth → rate limit → engagement scope → dry-run → approval → concurrency limiter → cache**.

- **Rate limiting** (token bucket, `REDHANDS_RATE_LIMIT=10/s`, burst 20) applies per request; a long call still consumed one token at admission — not a problem for one 30-minute campaign.
- **Concurrency limiter** (`pkg/execution/limiter.go:33-58`): each in-flight call holds one of `REDHANDS_MAX_CONCURRENT=4` active slots and a per-call deadline of `REDHANDS_TIMEOUT` (5 m default). **A blocking multi-minute campaign tool would monopolize a slot and die at the timeout. ⇒ decompose into start/status/results.**
- **Caching** is only applied when `policy.ReadOnly && policy.Cacheable` (`middleware.go:38-48`), keyed by caller identity + engagement. README:826 confirms: "Caching is limited to pure MITRE/risk-score lookups, never scans or state-changing tools." ⇒ only `blocktack_matrix` / `blocktack_capabilities` may set `Cacheable: true`.
- **Audit logging**: every direct call and workflow step is logged as JSONL `{id,timestamp,actor,action,tool,params,result,duration_ms,error}` (`pkg/audit/event.go:9-17`; README:888). Duration is whatever the call took; a background-start call audits quickly, and the campaign's own lifecycle shows up as start/status/results calls. No incompatibility with long-running work — but see §5 (R8, two-log story).
- **Async/background support: yes, two tiers.**
  1. *Managed background processes* (`BackgroundManager`, `pkg/executor/background.go:52-66`): `Start(ctx, binary, args, stdoutPath, stderrPath)` spawns a detached process group (stdout/stderr streamed to files, 256 MiB per-stream cap — `background.go:20,133-134`), `Status(id)`/`List()` return live state incl. exit code and truncation flags (`background.go:33-41,221-250`), `Stop(id)` = SIGTERM→SIGKILL to the group (`background.go:183-218`), `StopAll()` on server shutdown (`background.go:252-263`; wired in `cmd/redhands/main.go:43-47`). Used today by kubedagger/barzakh/telecom/aegis start/stop/status tools (`registry.go:269-302,333-343,368-375`).
  2. *Tasks extension* (`pkg/mcp/tasks.go`, README:639-653): async campaigns of RedHands *tools* with polling via `tasks/get` (`working|input_required|completed|failed|cancelled` — `tasks.go:126-208`) and cooperative cancel. This is for RedHands' own multi-tool campaigns, not for wrapping one foreign binary; a BlockTack campaign should use tier 1. (Tier 2 could later wrap a BlockTack campaign *as a step* in a RedHands campaign.)

### 1.5b Plugin-as-adapter tradeoff (question asked explicitly)

| | Go toolset in `tools/blocktack/` | JSON plugin in `plugins/` |
|---|---|---|
| Guardrails | reviewed policy per tool; safe mode enforced in tool code; no `--unsafe` exposure | ConservativePolicy ⇒ **every call approval-gated**; no way to distinguish matrix-lookup from campaign-launch |
| Long-running | BackgroundManager start/status/stop | impossible (bounded executor only) |
| Structured parsing | hand-written findings→JSON rendering, StructuredContent | raw fenced stdout |
| Chaining ergonomics | deliberate fenced-JSON contract | accidental stdout text |
| Maintenance | Go code, tests, livecheck entry | one JSON file |
| Verdict | **primary** | acceptable for a 1-day demo, supersede immediately |

---

## 2. BlockTack's current CLI ergonomics

### 2.1 Machine-readable output today

Command-by-command from `cmd/blocktack/main.go`:

| Command | stdout today | JSON available? | Notes |
|---|---|---|---|
| `matrix` | human text (taxonomy listing) — `main.go:93-102` | **No** — needs `--json` | pure local read |
| `recon` | SARIF XML on stdout by default; findings JSON via `--out FILE` — `main.go:124-129` | Partial (SARIF or file) | prints progress to stderr (`main.go:125`) |
| `scan` | SARIF stdout / `--out FILE` — `main.go:172-179` | Partial | creates temp workdir, self-cleans (`main.go:151-155`); stderr warnings per adapter (`main.go:170-174`) |
| `campaign` | nothing on stdout; `runs/campaigns/<ts>-<name>/` artifacts + human log to **stderr** — `main.go:205-212`, `runner.go:284-288` | Findings/killchains JSON *files* only, written at the very end (`runner.go:80-91`) | blocking; background shell steps killed at end (`runner.go:276-282`) |
| `node-audit` | SARIF stdout / `--out FILE` — `main.go:234-242` | Partial | modules: `all, cve-check, rpc-fuzz, mempool-analysis, peer-analysis` (`main.go:218`) |
| `report` | markdown to `--out` file (default `report.md`) — `main.go:245-283` | No (it *consumes* JSON) | `--engagement` mode adds killchains/target context (`main.go:286-318`) |

So: findings data is already JSON-encodable (`internal/core/finding.go`, SARIF writer `core.WriteSARIF`), but **there is no `--json` "results object" mode on stdout** and no campaign progress channel other than human stderr lines.

### 2.2 Exit codes and error reporting

- Usage errors / unknown command: **exit 2** (`main.go:29,50-52`). Any command error: **exit 1** with `error: <message>` on stderr (`main.go:54-57`). Success: 0.
- Errors are **never structured**; a plain string. Critically, **guardrail refusals are indistinguishable from any other error** at the exit-code level: "no authorization block", "authorization expired", "safe mode: endpoint ... neither local nor listed" all surface as exit 1 prose from `ValidateSafeMode` (`internal/core/target.go:120-164`).
- The authorization check **lives in BlockTack code**, not the CLI shell: `core.Target.ValidateSafeMode(safeMode)` at `internal/core/target.go:113-164` (block presence :121-132, expiry :133-138, loopback/liveTargets confinement :142-162 with `hostIsLocal` :166-181), and is invoked by every command path (`main.go:121,148,231`) *and* again defensively inside `playbook.Runner.Run` (`internal/playbook/runner.go:39`). **Even a mis-configured RedHands tool cannot get BlockTack to act on an unauthorized target** — the `--unsafe` flag would have to be passed explicitly, and the spec below never passes it.

### 2.3 Guardrail / side-effect map of candidate operations

| Operation | Safe by default? | Blocking? | Filesystem side effects | Network |
|---|---|---|---|---|
| capabilities (introspection) | yes | <1 s | none | none |
| matrix | yes | <1 s | none | none |
| validate-target | yes (dry Load+Validate) | <1 s | none | DNS lookups only for endpoint hostnames (`target.go:171`) |
| recon | yes — safe-mode confined (`main.go:121`) | seconds | none unless `--out` | target RPC, loopback/allow-list |
| scan (adapters) | yes — pure static analysis | seconds–minutes | temp dir, self-cleaned | none (slither is local) |
| node-audit `--module X` | yes — safe-mode confined | seconds–minutes | none unless `--out` | RPC (rpc-fuzz, mempool, peer modules) |
| campaign | safe-mode confined, but **executes attack playbook steps** (shell, engines, adapters) | **minutes–hours** (anvil forks, geth swarms) | creates `runs/campaigns/<ts>-<name>/`; **spawns background processes** (anvil) via `background: true` steps (`runner.go:145-173`) | target RPC + any playbook shell commands |
| report --engagement | yes | seconds | writes the report file | none |
| engine direct call | depends on action; safe-mode confined if given a target | seconds | none (stdout findings) | target RPC |

Verdict: everything except `campaign` is synchronously bounded and MCP-tool-shaped as-is. `campaign` must become start/status/results.

---

## 3. Recommended architecture — decision

**Pick (a): RedHands-side Go wrapper toolset invoking `bin/blocktack` subprocesses.**

Justification, against the stated criteria:

1. **Maintenance / pattern-fit.** RedHands already maintains ~36 hand-written binary-wrapper toolsets with shared executor, allowlist, policy table, audit, tests, and a live-CLI-drift test suite (`tools/livecheck/`, README:910-951). A `blocktack` toolset is one more instance of a solved, reviewed pattern — including the *hard* part (long-running daemons), which `BackgroundManager` already handles for aegis/telecom/barzakh/kubedagger. A native MCP server mode in BlockTack would have to re-implement or forgo all of that.
2. **Deployment.** No new process model, no new transport, no new auth surface. BlockTack ships as a single static Go binary + two Rust engines; it lands on PATH (allowlist entry `"blocktack"` in `internal/binaries/binaries.go`) exactly like barzakh/staticzero/aegis-shadow release binaries do (README:112-131, 973).
3. **Guardrails.** The tool layer is where annotations/policies live (§1.1); the *binary* layer is where authorization enforcement lives (§2.2). Keeping BlockTack as a subprocess preserves both: RedHands policies constrain *who may call what*, BlockTack code constrains *what the binary will ever touch*. A `blocktack serve-mcp` (option b) would place both enforcement points in one binary and detach it from RedHands' engagement-scope, approval, dry-run, and rate-limit middleware — strictly worse for the stated design ("RedHands supplies the intelligence; BlockTack supplies deterministic execution + guardrails").
4. **Code sharing is not a good argument for option (b).** Both are Go, but: different modules (`github.com/blocktack/blocktack` vs `github.com/yasindce1998/redhands`, go.mod files), different toolchains (BlockTack `go 1.27`; RedHands `go 1.26.11` with 1.27 allowed — README:155), and every BlockTack package that matters lives under `internal/` (Go forbids cross-module `internal/` imports). Sharing would require promoting BlockTack internals to `pkg/` — a large refactor for zero benefit under architecture (a).
5. **How much RedHands owns.** RedHands owns: catalog, schemas, policies, audit, scope, chaining, async. BlockTack owns: authorization enforcement, taxonomy, engines, findings, reports. Clean seam = argv + stdout JSON.
6. **Hybrid note.** The JSON plugin system (§1.2.2) can stand up `blocktack_matrix`/`blocktack_capabilities` in an afternoon as a smoke test, but should be treated as scaffolding only (no policy control, no background support).

**BlockTack-side posture:** BlockTack remains a pure CLI. The only BlockTack-side "API" additions are additive output modes (§4.2) — the same CLI stays fully human-usable. AI planning stays out, per the design constraint; nothing in this spec adds inference, planning, or LLM-facing behavior to BlockTack.

---

## 4. BlockTack changes required (ordered, minimal-first)

### G0. Install surface (no code change)
Install `bin/blocktack` on PATH (e.g. `/usr/local/bin/blocktack`) and ensure the repo checkout lives at a stable path. Add `"blocktack"` to the allowlist name list in `/home/yasin/RedHands/internal/binaries/binaries.go:34-64`.

### G1. Executable-from-anywhere (the one cross-cutting gap)
**Problem:** `core.RepoRoot()` (`internal/core/target.go:183-199`) and `enginePath` (`runner.go:290-297`) resolve taxonomy (`taxonomy/blocktack-matrix.yaml`), adapters (`adapters/`), and engines (`engine-*/target/release/…`) from `$BLOCKTACK_ROOT` or cwd. RedHands' executor cannot set cwd or env for the child (`pkg/executor/executor.go:26-28` — `Run(ctx, binary, args...)` only).
**Fix (choose one):**
- *Preferred:* extend RedHands' `Executor`/`BackgroundManager` with optional `Dir`/`Env` (additive: `RunIn(ctx, dir, env, binary, args...)` or an options struct). Touches `pkg/executor/executor.go`, `pkg/executor/background.go`, `pkg/executor/mock.go` (~40 lines, all MockExecutor call sites in `tools/**` tests unchanged if the old signature is kept).
- *Fallback:* ship a 5-line shell wrapper `/usr/local/bin/blocktack-mcp` that `exec blocktack "$@"` after `export BLOCKTACK_ROOT=/opt/blocktack`, allowlist *that* name, and pass absolute `--taxonomy` paths.
BlockTack change: none strictly required, but accepting `--taxonomy` (already exists, `main.go:84`) everywhere it matters + honoring `BLOCKTACK_ROOT` (already exists) is what makes G1 cheap.

### G2. `capabilities` introspection subcommand → **`main.go`** (new `cmdCapabilities`)
Output JSON object: `{version, root, commands[], engines[] (probe `enginePath` for each of ["blocktack-evm","blocktack-solana"]), adapters[] (from `adapter.Names()`, `internal/adapter/adapter.go:38-45`), nodeaudit_modules[] ({"all","cve-check","rpc-fuzz","mempool-analysis","peer-analysis"} — `main.go:218`), taxonomy:{version, layers, weaknesses} (from `core.LoadTaxonomy`)}`.
No target needed; read-only; exit 0/1. This is what the MCP `blocktack_capabilities` tool renders, and it lets RedHands' AI plan against a *live* engine inventory instead of hard-coded knowledge.

### G3. `--json` machine output for `matrix` (+ new `validate-target`)
- `matrix --json`: emit the taxonomy as JSON (same data as text mode, `main.go:82-104`).
- New `validate-target --target FILE [--unsafe]`: run `core.LoadTarget` + `ValidateSafeMode(!unsafe)` (`target.go:83-99,120-164`) and print a JSON verdict `{valid, name, chain, endpoints[], authorization:{declared,authorizedBy,scope,expires,liveTargets}, violations[]}`. Dry by construction — it never contacts endpoints (only classifies hostnames). This is the tool an AI must call **before** anything else; it also gives RedHands the endpoint list to feed its engagement scope middleware (§6).

### G4. Structured errors + stable exit codes → **`main.go:54-57`**
Keep human prose on stderr, but add:
- exit **3** reserved for guardrail refusal (detect by wrapping `ValidateSafeMode` errors in a typed error, e.g. `core.ErrGuardrail`, checked in `main.go:54-57`),
- optional `--json-errors` (or `BLOCKTACK_JSON=1` env, convenient for BackgroundManager-launched processes) printing one JSON object to stderr: `{"error":{"code":"unauthorized_target|expired_authorization|unsafe_endpoint|invalid_target|engine_missing|...","message":"...","target":"..."}}`.
Rationale: RedHands wrappers can then map BlockTack's own refusal codes into clear MCP error text instead of regexing prose, and audits become greppable.

### G5. Findings-JSON on stdout → **`main.go:106-130,132-180,215-243`**
Add `--emit findings-json|sarif` (default sarif, preserving current behavior) to `recon`, `scan`, `node-audit` so the tool wrapper gets **machine-native findings on stdout** instead of parsing SARIF XML or requiring `--out` files. The findings struct already JSON-marshals (`internal/core/finding.go`; `core.SaveFindingsJSON` writes it today).

### G6. Campaign progress + status channel → **`internal/playbook/runner.go:38-109,284-288`**
Two additive changes to `Runner`:
1. `--progress-json` (flag threaded from `main.go:182-213`): alongside the human stderr log (`logf`, `runner.go:284-288`), write **JSON-lines events to stdout**: `{"event":"started","run_dir":...,"target":...,"playbook":...,"steps":N}`, `{"event":"step_started","id":...,"tactic":...}`, `{"event":"step_finished","id":...,"ok":bool,"findings":n}`, `{"event":"killchain","id":...,"severity":...}`, `{"event":"finished","findings":N,"exit":"ok|guardrail|error"}`. stdout is otherwise unused by campaign today (`main.go:205-212` only prints to stderr) — this is a clean channel.
2. **Crash-resilient status file:** after each step, atomically rewrite `<run_dir>/status.json` (`{state:"running|completed|failed", started_at, updated_at, current_step, steps_done:[{id,ok}], findings_so_far}` — runner already loops over steps at `runner.go:56-64`). Today `findings.json`/`killchains.json` appear **only at the end** (`runner.go:80-91`), so a killed campaign leaves nothing machine-readable; `status.json` fixes the "background process died mid-run" story.
Also print the run_dir as the **first** stdout event (mirrors how RedHands `campaign_start` surfaces workflow_id in the first line for polling — `tools/campaign/start.go` description, README:641).

### G7. Optional (phase 2): `campaign status --out-dir D` subcommand
Reads `status.json` + `BackgroundStatus`-independent facts so a *third party* could also poll without RedHands. Not required for v1 because RedHands' `BackgroundManager.Status` + JSON-lines tail covers it.

No changes are needed to: engines (stdin JSON job → stdout findings contract at `engine-evm/src/main.rs:1-12` is already ideal for `blocktack_engine_call`), adapters (SARIF contract, `internal/adapter/adapter.go:23-24`), report, or the taxonomy.

---

## 5. Tool table (RedHands `blocktack` toolset)

Naming follows the observed `<toolset>_<verb>_<object>` convention (`aegis_defense_start`, `telecom_correlator_status`, `barzakh_server_stop`, `campaign_status`). All wrapper code lives in `tools/blocktack/`; registration in `internal/registry/registry.go` (new gated block, ProcMgr-guarded for the daemon triad, mirroring `registry.go:368-376`); policies in `internal/registry/policy.go`.

All target-taking tools accept `target` (absolute path to the target YAML). They additionally accept an optional `targets: [rpc-url, ...]` array (copied from the validated target's endpoints — obtainable via `blocktack_validate_target`) so that RedHands' engagement scope middleware can check network hosts: `extractTargets` reads `target/targets/host/url/endpoint/...` keys (`pkg/engagement/middleware.go:30-56`), and a file path alone would not be scope-checked. The tools themselves also pass `--taxonomy <abs>` and run under G1's cwd/env support.

| # | Tool | Inputs (schema summary) | Output | Policy (`ToolPolicy`) → annotations | Blocking | Guardrail behavior |
|---|---|---|---|---|---|---|
| 1 | `blocktack_capabilities` | — | JSON: version, engines, adapters, modules, taxonomy summary | `{ReadOnly, RetrySafe, Cacheable}` → readOnly, idempotent, cached | sync <1 s | none needed (pure read) |
| 2 | `blocktack_matrix` | optional `weakness` id filter | taxonomy layer/weakness entries (fenced JSON + StructuredContent) | `{ReadOnly, RetrySafe, Cacheable}` | sync <1 s | none; pure lookup (an AI uses it to ground playbook/weakness reasoning) |
| 3 | `blocktack_validate_target` | `target` (path), `targets` (for scope-check) | JSON verdict incl. authorization block + endpoint list; `violations[]` on failure | `{ReadOnly, RetrySafe}` (host classification does DNS lookups, not connections) | sync | runs `ValidateSafeMode` in **safe mode only**; never passes `--unsafe` |
| 4 | `blocktack_recon` | `target`, optional `out_dir`, `targets` | findings array (fenced JSON + StructuredContent); SARIF file when `out_dir` | `{NetworkAccess}` (like `subfinder_enum`, `policy.go:33-35`) | sync, bounded by REDHANDS_TIMEOUT | BlockTack safe-mode check runs inside the binary (exit 3 → mapped error) |
| 5 | `blocktack_scan` | `target`, `adapters` (enum: slither, foundry — validated against `capabilities`), `targets` | findings array | `{}` (local, writes temp files) — matches `barzakh_scan` precedent (`policy.go:38`) | sync; slither can take minutes — acceptable within a raised `REDHANDS_TIMEOUT` | BlockTack guardrails; unknown adapter rejected in wrapper |
| 6 | `blocktack_node_audit` | `target`, `module` (enum: all, cve-check, rpc-fuzz, mempool-analysis, peer-analysis), `targets` | findings array | `{NetworkAccess}` | sync, bounded | safe mode enforced in binary; module enum validated in wrapper |
| 7 | `blocktack_engine_call` | `engine` (enum: blocktack-evm, blocktack-solana), `action` (string, validated per engine), `options` (object), `rpc_url` (optional override of target endpoints; safe-mode checked by the wrapper against loopback/liveTargets via validate_target-style logic) | engine findings array (engine contract: stdin JSON job → stdout findings JSON, `engine-evm/src/main.rs:1-12`) | `{NetworkAccess}` | sync, bounded | wrapper refuses non-loopback/unlisted RPC URLs; no target file needed |
| 8 | `blocktack_campaign_start` | `target`, `playbook` (path), `out_dir` (required, like aegis `alerts_dir` — validated dir), `targets` | **returns immediately**: fenced JSON `{process_id, run_dir, playbook, target}` (chainable `${step.json.process_id}`) + `StructuredContent` | `{NetworkAccess}` (safe mode constrains to loopback/allow-list; the authorization block in the target file *is* the operator approval artifact, enforced in BlockTack code — `target.go:120-141`) | **async** — `BackgroundManager.Start(ctx, "blocktack", ["campaign", "--target", t, "--playbook", p, "--out-dir", d, "--progress-json"], stdoutPath, stderrPath)`; stdout = JSON-lines progress file, stderr = human log | **never passes `--unsafe`**; refuses to start if target validation fails (wrapper calls the same `validate-target` logic first); refuses a second concurrent campaign while one `blocktack` process is `Running` in `mgr.List()` (port-collision guard, §5 R6) |
| 9 | `blocktack_campaign_status` | `process_id` (omit → list all blocktack processes) | live state: running, pid, uptime/exit code, JSON-lines step progress (last N events parsed from stdout file), `run_dir` | `{ReadOnly, RetrySafe}` (daemon-status precedent, `policy.go:67-69`) | sync | read-only |
| 10 | `blocktack_campaign_results` | `run_dir` (validated path), optional `include_log` (tail campaign.log) | findings.json array + killchains.json + pointer to SARIF (fenced JSON + StructuredContent so `record` rules and downstream `report` tools can consume) | `{ReadOnly, RetrySafe}` | sync | read-only file reads inside the declared `out_dir` tree only (path-validated) |
| 11 | `blocktack_report` | `findings` (JSON array or path(s)), `engagement` (bool), optional `target`, `killchains`, `out_dir` | markdown report path + summary counts | `{}` (writes one file — `barzack_report` precedent `policy.go:111`) | sync | output confined to `out_dir`; report is deterministic (no AI text generation — summaries come from `internal/report`) |

Notes on the table:
- **Deliberately absent:** any tool parameter that maps to BlockTack's `--unsafe`. The safe/unsafe decision is an operator decision made in the target file + `authorization.liveTargets`, enforced by BlockTack code. If operators later need unsafe-mode MCP access, the precedent is a separate, approval-gated tool (like `aegis_offense_start` vs `aegis_defense_start`, `policy.go:55-57`) — never a flag on the shared tool.
- **Blocking vs async:** only `campaign_start` is async, exactly mirroring `aegis_defense_start` / `telecom_offense_start`. Everything else is a bounded sync call under the standard middleware chain.
- **Structured dataflow:** tools 4-7 and 10 emit fenced JSON in the first content block (aegis convention, `defense_start.go:228-237`) so `${step.json...}` placeholders and campaign `record` rules work unchanged.

---

## 6. Example tool definition (RedHands native format)

`tools/blocktack/campaign_start.go` — follows the real structure of `tools/aegis/defense_start.go` (constructor, allowlisted binary, strict enum validation, errorResult helper, fenced JSON for chaining):

```go
package blocktack

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// campaignBinary is the allowlist name of the BlockTack CLI.
const campaignBinary = "blocktack"

// CampaignStartTool launches a BlockTack playbook as a managed background
// process via the BackgroundManager, which enforces the same binary
// allowlist and argument validation as the regular executor.
type CampaignStartTool struct {
	mgr *executor.BackgroundManager
}

func NewCampaignStart(mgr *executor.BackgroundManager) *CampaignStartTool {
	return &CampaignStartTool{mgr: mgr}
}

func (t *CampaignStartTool) Name() string { return "blocktack_campaign_start" }

func (t *CampaignStartTool) Description() string {
	return "Start a BlockTack blockchain adversary-simulation campaign (playbook execution: " +
		"engine steps, adapters, shell setup like anvil forks) as a managed background process. " +
		"Returns immediately with process_id and run_dir; poll blocktack_campaign_status and fetch " +
		"findings with blocktack_campaign_results. Safe mode only: the tool never passes --unsafe; " +
		"BlockTack itself refuses any target whose YAML lacks an unexpired authorization block or " +
		"whose endpoints are neither loopback nor listed in authorization.liveTargets — call " +
		"blocktack_validate_target first to confirm the target is runnable. Only one BlockTack " +
		"campaign may run at a time (anvil forks bind fixed ports). Output: JSON-lines progress on " +
		"<out_dir>/campaign-<id>.out; human log on <out_dir>/campaign-<id>.err. For authorized " +
		"assessments only — the target's authorization block is the record of permission."
}

func (t *CampaignStartTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Absolute path to the BlockTack target YAML (must carry a valid authorization block)"
			},
			"playbook": {
				"type": "string",
				"description": "Absolute path to the playbook YAML (e.g. playbooks/evm/oracle-manipulation.yaml)"
			},
			"out_dir": {
				"type": "string",
				"description": "Existing directory for campaign output and process logs; run artifacts land in a timestamped subdirectory (findings.json, findings.sarif, killchains.json, campaign.log)"
			},
			"targets": {
				"type": "array",
				"items": {"type": "string"},
				"description": "Optional list of the target's RPC endpoint URLs; checked against the active engagement scope like any other tool target"
			}
		},
		"required": ["target", "playbook", "out_dir"]
	}`)
}

func (t *CampaignStartTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Target   string   `json:"target"`
		Playbook string   `json:"playbook"`
		OutDir   string   `json:"out_dir"`
		Targets  []string `json:"targets"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}
	if err := validateExistingFile(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateExistingFile(input.Playbook, "playbook"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateOutputDir(input.OutDir, "out_dir"); err != nil {
		return errorResult(err.Error()), nil
	}
	for _, url := range input.Targets {
		if err := validateSafeString(url, "targets entry"); err != nil {
			return errorResult(err.Error()), nil
		}
	}

	// Port-collision guard: refuse a second concurrent BlockTack campaign.
	for _, st := range t.mgr.List() {
		if st.Binary == campaignBinary && st.Running {
			return errorResult(fmt.Sprintf(
				"blocktack campaign %s is still running; wait for it or poll blocktack_campaign_status",
				st.ID)), nil
		}
	}

	// Safe mode is not parameterizable here by design: no --unsafe argument
	// is ever emitted. Authorization is enforced inside blocktack (exit 3).
	suffix := randomSuffix()
	stdoutPath := filepath.Join(input.OutDir, "campaign-"+suffix+".out")
	stderrPath := filepath.Join(input.OutDir, "campaign-"+suffix+".err")

	args := []string{
		"campaign",
		"--target", input.Target,
		"--playbook", input.Playbook,
		"--out-dir", input.OutDir,
		"--progress-json",
	}
	proc, err := t.mgr.Start(ctx, campaignBinary, args, stdoutPath, stderrPath)
	if err != nil {
		return errorResult("failed to start " + campaignBinary + ": " + err.Error()), nil
	}

	var sb strings.Builder
	sb.WriteString("## BlockTack Campaign Started\n\n")
	daemonJSON, _ := json.Marshal(map[string]any{
		"process_id":  proc.ID,
		"pid":         proc.PID,
		"binary":      campaignBinary,
		"run_dir":     input.OutDir,
		"stdout_path": stdoutPath,
		"stderr_path": stderrPath,
	})
	fmt.Fprintf(&sb, "```json\n%s\n```\n\n", daemonJSON)
	fmt.Fprintf(&sb, "- **Process ID:** %s\n", proc.ID)
	fmt.Fprintf(&sb, "- **Run dir:** %s\n", input.OutDir)
	sb.WriteString("\nNotes:\n\n")
	fmt.Fprintf(&sb, "- `blocktack_campaign_status` with process_id `%s` reports live progress\n", proc.ID)
	fmt.Fprintf(&sb, "- `blocktack_campaign_results` with run_dir `%s` fetches findings.json / killchains.json when finished\n", input.OutDir)
	sb.WriteString("- Safe mode only; the target's authorization block is enforced by blocktack itself.\n")

	return &mcp.ToolResult{
		Content:           []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
		StructuredContent: daemonJSON,
	}, nil
}
```

Companion registration + policy entries (the two-line diff in RedHands):

```go
// internal/registry/registry.go — inside RegisterAll:
if d.Cfg.ToolsetEnabled("blocktack") {
	register(blocktack.NewCapabilities())
	register(blocktack.NewMatrix())
	register(blocktack.NewValidateTarget())
	register(blocktack.NewRecon(d.Exec))
	register(blocktack.NewScan(d.Exec))
	register(blocktack.NewNodeAudit(d.Exec))
	register(blocktack.NewEngineCall(d.Exec))
	if d.ProcMgr != nil {
		register(blocktack.NewCampaignStart(d.ProcMgr))
		register(blocktack.NewCampaignStop(d.ProcMgr))   // optional v1.1
		register(blocktack.NewCampaignStatus(d.ProcMgr))
	}
	register(blocktack.NewCampaignResults())
	register(blocktack.NewReport(d.Exec))
}

// internal/registry/policy.go — reviewed-capability table:
for _, name := range []string{
	"blocktack_capabilities", "blocktack_matrix", "blocktack_validate_target",
	"blocktack_campaign_status", "blocktack_campaign_results",
} {
	policies[name] = mcp.ToolPolicy{ReadOnly: true, RetrySafe: true}
}
policies["blocktack_capabilities"] = mcp.ToolPolicy{ReadOnly: true, RetrySafe: true, Cacheable: true}
policies["blocktack_matrix"] = mcp.ToolPolicy{ReadOnly: true, RetrySafe: true, Cacheable: true}
for _, name := range []string{"blocktack_recon", "blocktack_node_audit", "blocktack_engine_call", "blocktack_campaign_start"} {
	policies[name] = mcp.ToolPolicy{NetworkAccess: true}
}
policies["blocktack_scan"] = mcp.ToolPolicy{}
policies["blocktack_report"] = mcp.ToolPolicy{}
```

(`Cacheable: true` on lookups follows the `mitre_lookup`/`risk_score_calculate` precedent, `policy.go:25-27`; the cache middleware only honors it for ReadOnly tools — `internal/app/middleware.go:47`.)

---

## 7. Risks / unknowns

- **R1 — Long-running campaign & timeout semantics.** BackgroundManager processes deliberately outlive the RPC request and are *not* subject to `REDHANDS_TIMEOUT` (`background.go:128-131`); the campaign instead dies only if RedHands exits (`StopAll` kills the process group, `main.go:47`, `background.go:96`). Unknown/risk: an operator shutting down RedHands mid-campaign kills anvil forks abruptly; findings.json may never be written (end-of-run only, `runner.go:80-91`). Mitigated by G6's `status.json` per-step checkpoint.
- **R2 — Output truncation.** Sync tools are capped at `REDHANDS_MAX_OUTPUT` (10 MB default, `config.go:81`) across both streams (`executor.go:55-58`); a `node-audit` over a large contract set emitting findings-JSON could bump into it (the wrapper should pass `--out FILE` for large scans and return the file path + summary counts instead of full JSON). Background streams have a much larger 256 MiB per-stream cap (`background.go:20`) — JSON-lines progress is safe there.
- **R3 — Concurrent campaigns & port collisions (verified).** BlockTack playbooks hard-code `--port 8545` (e.g. `playbooks/evm/curve-vyper-incident-replay.yaml` step `env-up`) and shipped targets point at `http://127.0.0.1:8545` (`examples/targets/local-anvil.yaml:12`). Two concurrent campaigns would race for anvil's port. The claimed additional range 8555–8558 was **not found anywhere in BlockTack code or docs** (grep across `*.go`, `*.rs`, `*.yaml`, `*.md` returns nothing) — treat it as unverified. Mitigations in the spec: `campaign_start` refuses a second running `blocktack` process (see example tool); longer-term, BlockTack could support a `--rpc-port`/`${BLOCKTACK_RPC_PORT}` expansion in playbook shell steps (today only `BLOCKTACK_OUT_DIR` is exported to shell steps, `runner.go:157`).
- **R4 — Executor cwd/env gap (G1).** Without Dir/Env support (or the wrapper-script fallback), BlockTack cannot find its taxonomy/adapters/engines when RedHands runs from a different cwd. This is the highest-priority enabler; verify before writing the toolset.
- **R5 — Engine binary presence.** Rust engines must be pre-built (`make engine`; `enginePath` expects `engine-*/target/release/…`, `runner.go:290-297`). `blocktack_capabilities` reports engine presence so the AI never plans around a missing engine; wrappers should surface `engine_missing` errors distinctly (G4).
- **R6 — Playbook shell steps are arbitrary commands.** A campaign's `run.type: shell` steps execute attacker-chosen shell commands (`runner.go:147-185`) — inside BlockTack, safe-mode confines *endpoints*, not shell step contents. The MCP tool therefore inherits playbook trust from the filesystem: RedHands' wrapper should require playbook/target paths under an operator-designated roots (e.g. `BLOCKTACK_PLAYBOOKS_DIR`), and the tool description must say that playbook files are operator-authored, like `msf_resource_run` treats `.rc` files (`tools/msf/resource_run.go`; README:485). Consider `RequiresApproval: true` on `blocktack_campaign_start` if your deployment allows AI-authored playbooks.
- **R7 — Scope-middleware semantics.** `extractTargets` pulls network hosts from param keys (`engagement/middleware.go:47`); a bare file path won't be scope-checked. The `targets` parameter convention in §5 fixes this, but it relies on the caller passing the endpoints — `blocktack_validate_target` output (which includes the resolved endpoint list) should be chained into it. Alternatively, add a `blocktack_` name prefix to the "local" exemption list (`engagement/middleware.go:18`) — **not recommended**, since BlockTack genuinely does network I/O.
- **R8 — Audit-log compatibility.** RedHands audits tool/params/result/duration (`pkg/audit/event.go:9-17`) — BlockTack calls audit fine, but params contain file paths, not hosts, and BlockTack's own `campaign.log`/`campaign.jsonl` live in the run dir. Two audit trails result; document that the run dir is the evidence of record and RedHands' audit is the access log. Do not duplicate BlockTack findings into RedHands' audit events.
- **R9 — Secrets in target YAML.** Target files may carry RPC credentials for fork endpoints; `BackgroundManager` redacts values after known secret flags only (`background.go:71-91`) — none of which BlockTack uses (flags are `--target/--playbook/...` paths). Paths to credentialed YAML end up in audit logs and status output; acceptable for lab use, note it in the threat model.
- **R10 — Timezones of expiry.** `authorization.expires` is enforced with `time.Now()` (`target.go:136-138`) — a stale target file whose authorization lapsed will fail `blocktack_validate_target` first; make sure the AI's loop treats that as a hard stop, not a retry.
- **R11 — Plugin interim.** If a JSON-plugin smoke test is deployed first, remember plugins get `ConservativePolicy` (`server.go:94`) — every call will demand approval and `BackgroundManager`-based campaigns are impossible; plan the Go toolset before any real use.

---

## 8. Implementation checklist (ordered)

**BlockTack (all additive; ~1–2 days):**
1. G2 `capabilities --json` (`cmd/blocktack/main.go`).
2. G4 typed guardrail error + exit 3 + optional JSON error object (`main.go:54-57`, `internal/core/target.go`).
3. G3 `validate-target` + `matrix --json` (`main.go`).
4. G6 `--progress-json` + per-step `status.json` (`internal/playbook/runner.go`).
5. G5 `--emit findings-json` for recon/scan/node-audit (`main.go`).

**RedHands (~2–3 days):**
6. G1 executor Dir/Env support (or wrapper script decision).
7. Allowlist entry (`internal/binaries/binaries.go`).
8. `tools/blocktack/` package (11 tools, following §5/§6) + registry block + policy table entries.
9. Makefile `install-tools PROFILE=blocktack` + Docker image note (optional).
10. `tools/livecheck/table.go` entry so CLI-flag drift in BlockTack is caught by `make test-live` (README:950-952).

**Sequencing note:** G1 (env/cwd) → G2/G3/G4 (introspection + validation) are enough to ship the read-only half of the toolset (capabilities, matrix, validate-target, recon, scan, node-audit, report). G6 unlocks `campaign_start/status/results`, which is the centerpiece for AI-driven assessment loops.
