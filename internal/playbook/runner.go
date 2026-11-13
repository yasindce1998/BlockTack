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

	logLines []string
	findings []core.Finding
	bgProcs  []*exec.Cmd
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

	r.logf("campaign %q against target %q started %s",
		r.Playbook.Name, r.Target.Name, time.Now().UTC().Format(time.RFC3339))
	if r.Playbook.Description != "" {
		r.logf("  %s", r.Playbook.Description)
	}

	for _, step := range r.Playbook.Steps {
		r.logf("step %-24s tactic=%s  %s", step.ID, step.Tactic, step.Name)
		if step.Precondition != "" {
			r.logf("  precondition: %s", step.Precondition)
		}
		if err := r.runStep(ctx, step, stepsDir); err != nil {
			r.logf("  FAILED: %v", err)
		}
	}

	r.stopBackground()
	r.logf("campaign finished: %d findings", len(r.findings))
	for _, f := range r.findings {
		r.logf("  [%s] %s (%s)", f.Severity, f.Title, f.Weakness)
	}

	if err := core.SaveFindingsJSON(r.findings, filepath.Join(r.OutDir, "findings.json")); err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(r.OutDir, "findings.sarif"))
	if err != nil {
		return err
	}
	if err := core.WriteSARIF(f, r.findings); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.WriteFile(
		filepath.Join(r.OutDir, "campaign.log"),
		[]byte(strings.Join(r.logLines, "\n")+"\n"), 0o644,
	)
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
	return filepath.Join(core.RepoRoot(), "engine-evm", "target", "release", name)
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
