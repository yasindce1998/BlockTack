package playbook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/blocktack/blocktack/internal/adapter"
	"github.com/blocktack/blocktack/internal/core"
	"github.com/blocktack/blocktack/internal/correlate"
	"github.com/blocktack/blocktack/internal/nodeaudit"
)

// Runner executes a playbook against a target, collecting findings and
// per-step artifacts into an output directory.
type Runner struct {
	Target   *core.Target
	Playbook *Playbook
	OutDir   string
	// Unsafe disables the safe-mode endpoint restriction (still requires
	// a valid authorization block). Wire this to an explicit --unsafe flag.
	Unsafe bool
	// ProgressJSON emits machine-readable JSON-lines progress events to
	// stdout (started/step_started/step_finished/killchain/finished).
	// stdout is otherwise unused by campaigns; the human log stays on
	// stderr. Consumers (e.g. MCP wrappers) tail this channel and the
	// crash-resilient status.json written after every step.
	ProgressJSON bool

	logLines  []string
	findings  []core.Finding
	bgProcs   []*exec.Cmd
	stepsDone []stepOutcome
	startedAt time.Time
}

// stepOutcome records one playbook step's result for status.json.
type stepOutcome struct {
	ID string `json:"id"`
	OK bool   `json:"ok"`
}

// Run executes the campaign. Step failures are recorded and the campaign
// continues; only guardrail violations abort it.
func (r *Runner) Run(ctx context.Context) error {
	if err := r.Target.ValidateSafeMode(!r.Unsafe); err != nil {
		return err
	}
	if err := os.MkdirAll(r.OutDir, 0o755); err != nil {
		return err
	}
	stepsDir := filepath.Join(r.OutDir, "steps")
	if err := os.MkdirAll(stepsDir, 0o755); err != nil {
		return err
	}

	r.startedAt = time.Now().UTC()
	r.logf("campaign %q against target %q started %s",
		r.Playbook.Name, r.Target.Name, r.startedAt.Format(time.RFC3339))
	if r.Playbook.Description != "" {
		r.logf("  %s", r.Playbook.Description)
	}
	r.emit(map[string]any{
		"event":     "started",
		"run_dir":   r.OutDir,
		"target":    r.Target.Name,
		"playbook":  r.Playbook.Name,
		"steps":     len(r.Playbook.Steps),
		"timestamp": r.startedAt.Format(time.RFC3339),
	})

	for _, step := range r.Playbook.Steps {
		r.logf("step %-24s tactic=%s  %s", step.ID, step.Tactic, step.Name)
		if step.Precondition != "" {
			r.logf("  precondition: %s", step.Precondition)
		}
		r.emit(map[string]any{
			"event":    "step_started",
			"id":       step.ID,
			"tactic":   step.Tactic,
			"name":     step.Name,
			"step":     len(r.stepsDone) + 1,
			"of_steps": len(r.Playbook.Steps),
		})
		before := len(r.findings)
		err := r.runStep(ctx, step, stepsDir)
		if err != nil {
			r.logf("  FAILED: %v", err)
		} else {
			r.logf("  ok — %d findings", len(r.findings)-before)
		}
		r.stepsDone = append(r.stepsDone, stepOutcome{ID: step.ID, OK: err == nil})
		r.emit(map[string]any{
			"event":          "step_finished",
			"id":             step.ID,
			"ok":             err == nil,
			"error":          errString(err),
			"findings":       len(r.findings) - before,
			"findings_total": len(r.findings),
		})
		r.writeStatus("running", step.ID)
	}

	r.stopBackground()

	// Correlate findings into kill chains and append composite findings.
	chains := correlate.Analyze(r.findings)
	for _, c := range chains {
		r.logf("kill chain: [%s] %s", c.Severity, c.Title)
		for _, s := range c.Stages {
			r.logf("  stage: %s (%s)", s.Description, s.FindingID)
		}
		if c.FinancialImpactEth != "" {
			r.logf("  financial impact: %s ETH (%s wei)", c.FinancialImpactEth, c.FinancialImpactWei)
		}
		r.emit(map[string]any{
			"event":                "killchain",
			"id":                   c.ID,
			"title":                c.Title,
			"severity":             c.Severity,
			"stages":               len(c.Stages),
			"financial_impact_eth": c.FinancialImpactEth,
		})
		r.findings = append(r.findings, chainFinding(c))
	}
	if len(chains) > 0 {
		if data, err := json.MarshalIndent(chains, "", "  "); err == nil {
			_ = os.WriteFile(filepath.Join(r.OutDir, "killchains.json"), data, 0o644)
		}
	}

	r.logf("campaign finished: %d findings", len(r.findings))
	for _, f := range r.findings {
		r.logf("  [%s] %s (%s)", f.Severity, f.Title, f.Weakness)
	}

	if err := core.SaveFindingsJSON(r.findings, filepath.Join(r.OutDir, "findings.json")); err != nil {
		r.writeStatus("failed", "")
		return err
	}
	f, err := os.Create(filepath.Join(r.OutDir, "findings.sarif"))
	if err != nil {
		r.writeStatus("failed", "")
		return err
	}
	if err := core.WriteSARIF(f, r.findings); err != nil {
		f.Close()
		r.writeStatus("failed", "")
		return err
	}
	if err := f.Close(); err != nil {
		r.writeStatus("failed", "")
		return err
	}
	if err := os.WriteFile(
		filepath.Join(r.OutDir, "campaign.log"),
		[]byte(strings.Join(r.logLines, "\n")+"\n"), 0o644,
	); err != nil {
		r.writeStatus("failed", "")
		return err
	}
	r.emit(map[string]any{
		"event":       "finished",
		"findings":    len(r.findings),
		"kill_chains": len(chains),
		"exit":        "ok",
		"run_dir":     r.OutDir,
	})
	r.writeStatus("completed", "")
	return nil
}

// emit writes one JSON-lines progress event to stdout when ProgressJSON
// is enabled. Best-effort: progress must never fail a campaign.
func (r *Runner) emit(ev map[string]any) {
	if !r.ProgressJSON {
		return
	}
	data, err := json.Marshal(ev)
	if err != nil {
		return
	}
	fmt.Fprintln(os.Stdout, string(data))
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// writeStatus atomically rewrites <run_dir>/status.json after every
// step, so a killed or crashed campaign still leaves machine-readable
// state behind (findings.json is only written at the very end).
func (r *Runner) writeStatus(state, currentStep string) {
	st := statusSnapshot{
		State:         state,
		StartedAt:     r.startedAt.Format(time.RFC3339),
		UpdatedAt:     time.Now().UTC().Format(time.RFC3339),
		Playbook:      r.Playbook.Name,
		Target:        r.Target.Name,
		CurrentStep:   currentStep,
		StepsDone:     append([]stepOutcome(nil), r.stepsDone...),
		StepsTotal:    len(r.Playbook.Steps),
		FindingsSoFar: len(r.findings),
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	final := filepath.Join(r.OutDir, "status.json")
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, final)
}

// StatusSnapshot is the crash-resilient campaign state written to
// status.json after each step.
type statusSnapshot struct {
	State         string        `json:"state"` // running | completed | failed
	StartedAt     string        `json:"started_at"`
	UpdatedAt     string        `json:"updated_at"`
	Playbook      string        `json:"playbook"`
	Target        string        `json:"target"`
	CurrentStep   string        `json:"current_step,omitempty"`
	StepsTotal    int           `json:"steps_total"`
	StepsDone     []stepOutcome `json:"steps_done"`
	FindingsSoFar int           `json:"findings_so_far"`
}

func (r *Runner) runStep(ctx context.Context, step Step, stepsDir string) error {
	switch step.Run.Type {
	case "manual":
		note := step.Run.Note
		if note == "" {
			note = "no note provided"
		}
		r.logf("  manual step: %s", note)
		return nil
	case "shell":
		return r.runShell(ctx, step, stepsDir)
	case "engine":
		return r.runEngine(ctx, step, stepsDir)
	case "adapter":
		return r.runAdapter(ctx, step)
	case "builtin":
		return r.runBuiltin(ctx, step)
	default:
		return fmt.Errorf("unknown run type %q", step.Run.Type)
	}
}

// runBuiltin executes a Go-resident audit module (see internal/nodeaudit).
func (r *Runner) runBuiltin(ctx context.Context, step Step) error {
	if step.Run.Action == "" {
		return fmt.Errorf("builtin step requires `action`")
	}
	findings, err := nodeaudit.Run(ctx, step.Run.Action, r.Target)
	if err != nil {
		return err
	}
	r.findings = append(r.findings, findings...)
	r.logf("  builtin %s returned %d findings", step.Run.Action, len(findings))
	return nil
}

func (r *Runner) runShell(ctx context.Context, step Step, stepsDir string) error {
	if step.Run.Command == "" {
		return fmt.Errorf("shell step requires `command`")
	}
	logFile := filepath.Join(stepsDir, step.ID+".log")
	// Environment expansion is left to the shell: step args are passed
	// verbatim so `sh -c` scripts can define and use their own variables.
	// BLOCKTACK_OUT_DIR is injected so steps can reference campaign
	// artifacts (e.g. logs of earlier steps).
	cmd := exec.CommandContext(ctx, step.Run.Command, step.Run.Args...)
	cmd.Env = append(os.Environ(), "BLOCKTACK_OUT_DIR="+r.OutDir)

	if step.Run.Background {
		f, err := os.Create(logFile)
		if err != nil {
			return err
		}
		cmd.Stdout = f
		cmd.Stderr = f
		if err := cmd.Start(); err != nil {
			f.Close()
			return err
		}
		r.bgProcs = append(r.bgProcs, cmd)
		r.logf("  started background process (pid %d), log: %s", cmd.Process.Pid, logFile)
		return nil
	}

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	_ = os.WriteFile(logFile, out.Bytes(), 0o644)
	if err != nil {
		return fmt.Errorf("%w — output tail: %s", err, tail(out.String(), 400))
	}
	r.logf("  ok — output tail: %s", tail(out.String(), 200))
	return nil
}

func (r *Runner) runEngine(ctx context.Context, step Step, stepsDir string) error {
	if step.Run.Engine == "" {
		return fmt.Errorf("engine step requires `engine`")
	}
	bin := enginePath(step.Run.Engine)
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("engine binary %s not found (build with `make engine`): %w", bin, err)
	}
	job := map[string]any{
		"action":  step.Run.Action,
		"options": step.Run.Options,
		"target": map[string]any{
			"name":      r.Target.Name,
			"chain":     r.Target.Chain,
			"endpoints": r.Target.Endpoints,
			"contracts": r.Target.Contracts,
		},
	}
	in, err := json.Marshal(job)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, bin)
	cmd.Stdin = bytes.NewReader(in)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w — stderr: %s", err, tail(stderr.String(), 400))
	}
	_ = os.WriteFile(filepath.Join(stepsDir, step.ID+".json"), stdout.Bytes(), 0o644)

	var findings []core.Finding
	if len(bytes.TrimSpace(stdout.Bytes())) > 0 {
		if err := json.Unmarshal(stdout.Bytes(), &findings); err != nil {
			return fmt.Errorf("parse engine output: %w", err)
		}
	}
	for i := range findings {
		findings[i].Normalize()
		if findings[i].Source == "" {
			findings[i].Source = step.Run.Engine
		}
	}
	r.findings = append(r.findings, findings...)
	r.logf("  engine returned %d findings", len(findings))
	return nil
}

func (r *Runner) runAdapter(ctx context.Context, step Step) error {
	if step.Run.Adapter == "" {
		return fmt.Errorf("adapter step requires `adapter`")
	}
	reg := adapter.Registry()
	a, ok := reg[step.Run.Adapter]
	if !ok {
		return fmt.Errorf("unknown adapter %q (available: %v)", step.Run.Adapter, adapter.Names())
	}
	findings, err := a.Run(ctx, r.Target, step.Run.Options, r.OutDir)
	if err != nil {
		return err
	}
	r.findings = append(r.findings, findings...)
	r.logf("  adapter %s returned %d findings", a.Name, len(findings))
	return nil
}

// chainFinding renders a kill chain as a first-class finding so it
// flows into reports like any other result.
func chainFinding(c correlate.KillChain) core.Finding {
	stages := make([]string, len(c.Stages))
	for i, s := range c.Stages {
		stages[i] = fmt.Sprintf("%s [%s]", s.Description, s.FindingID)
	}
	f := core.Finding{
		ID:          c.ID,
		Title:       c.Title,
		Severity:    c.Severity,
		Confidence:  core.ConfConfirmed,
		Description: c.Description + " Stages: " + strings.Join(stages, " -> ") + ".",
		Source:      "correlate",
	}
	if c.FinancialImpactEth != "" {
		f.Evidence = fmt.Sprintf("verified profit: %s ETH (%s wei)", c.FinancialImpactEth, c.FinancialImpactWei)
	}
	f.Normalize()
	return f
}

func (r *Runner) stopBackground() {
	for _, cmd := range r.bgProcs {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}
}

func (r *Runner) logf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	r.logLines = append(r.logLines, line)
	fmt.Fprintln(os.Stderr, line)
}

func enginePath(name string) string {
	if dir := os.Getenv("BLOCKTACK_ENGINES"); dir != "" {
		return filepath.Join(dir, name)
	}
	// Binary "blocktack-evm" lives in engine-evm/target/release/, etc.
	dir := "engine-" + strings.TrimPrefix(name, "blocktack-")
	return filepath.Join(core.RepoRoot(), dir, "target", "release", name)
}

func expandArgs(args []string) []string {
	return args // expansion is the shell's job; kept for API stability
}

var sanitizeRe = regexp.MustCompile(`[^a-z0-9-]+`)

// SanitizeName converts a playbook name into a filesystem-safe directory name.
func SanitizeName(name string) string {
	s := sanitizeRe.ReplaceAllString(strings.ToLower(name), "-")
	return strings.Trim(s, "-")
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}
