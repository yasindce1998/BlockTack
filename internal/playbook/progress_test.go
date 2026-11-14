package playbook

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blocktack/blocktack/internal/core"
)

// writeMiniFixture creates a target + playbook with two manual steps in
// t.TempDir() and returns the paths.
func writeMiniFixture(t *testing.T) (targetPath, playbookPath string) {
	t.Helper()
	dir := t.TempDir()
	target := "apiVersion: blocktack/v1\n" +
		"name: mini-target\n" +
		"chain: {type: evm, network: local, chainId: 31337}\n" +
		"endpoints:\n" +
		"  - {name: rpc, role: rpc, url: \"http://127.0.0.1:8545\"}\n" +
		"contracts: []\n" +
		"authorization:\n" +
		"  declared: true\n" +
		"  authorizedBy: self (local lab)\n" +
		"  scope: local fixture only\n" +
		"  expires: \"2099-01-01T00:00:00Z\"\n"
	playbook := "apiVersion: blocktack/v1\n" +
		"name: mini-playbook\n" +
		"steps:\n" +
		"  - id: step-one\n" +
		"    name: first\n" +
		"    tactic: recon\n" +
		"    run:\n" +
		"      type: manual\n" +
		"      note: no-op one\n" +
		"  - id: step-two\n" +
		"    name: second\n" +
		"    tactic: exploit\n" +
		"    run:\n" +
		"      type: manual\n" +
		"      note: no-op two\n"
	tp := filepath.Join(dir, "target.yaml")
	if err := os.WriteFile(tp, []byte(target), 0o644); err != nil {
		t.Fatal(err)
	}
	pp := filepath.Join(dir, "playbook.yaml")
	if err := os.WriteFile(pp, []byte(playbook), 0o644); err != nil {
		t.Fatal(err)
	}
	return tp, pp
}

// TestRunnerProgressJSONAndStatus verifies the machine-readable campaign
// channel: JSON-lines events on stdout and a crash-resilient
// status.json rewritten after every step.
func TestRunnerProgressJSONAndStatus(t *testing.T) {
	tp, pp := writeMiniFixture(t)
	tgt, err := core.LoadTarget(tp)
	if err != nil {
		t.Fatalf("load target: %v", err)
	}
	pb, err := Load(pp)
	if err != nil {
		t.Fatalf("load playbook: %v", err)
	}
	outDir := filepath.Join(t.TempDir(), "run")

	// Capture stdout during the run.
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	runner := &Runner{Target: tgt, Playbook: pb, OutDir: outDir, ProgressJSON: true}
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	w.Close()
	os.Stdout = old

	var events []map[string]any
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("progress line is not JSON: %q", line)
		}
		events = append(events, ev)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan stdout: %v", err)
	}

	// Event sequence: started, step_started/step_finished per step, finished.
	wantKinds := []string{
		"started", "step_started", "step_finished",
		"step_started", "step_finished", "finished",
	}
	if len(events) != len(wantKinds) {
		t.Fatalf("got %d events, want %d: %+v", len(events), len(wantKinds), events)
	}
	for i, ev := range events {
		if ev["event"] != wantKinds[i] {
			t.Errorf("event %d = %v, want %v", i, ev["event"], wantKinds[i])
		}
	}
	// The first event carries the run_dir (how wrappers learn where
	// artifacts land).
	if events[0]["run_dir"] != outDir {
		t.Errorf("started.run_dir = %v, want %s", events[0]["run_dir"], outDir)
	}
	// The finishing event counts findings (0 here) and reports ok.
	if events[len(events)-1]["exit"] != "ok" {
		t.Errorf("finished.exit = %v, want ok", events[len(events)-1]["exit"])
	}

	// status.json: completed, both steps recorded.
	data, err := os.ReadFile(filepath.Join(outDir, "status.json"))
	if err != nil {
		t.Fatalf("read status.json: %v", err)
	}
	var st statusSnapshot
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("parse status.json: %v", err)
	}
	if st.State != "completed" {
		t.Errorf("state = %q, want completed", st.State)
	}
	if len(st.StepsDone) != 2 {
		t.Fatalf("steps_done = %+v, want 2 entries", st.StepsDone)
	}
	for i, s := range st.StepsDone {
		if !s.OK {
			t.Errorf("steps_done[%d] (%s) not ok", i, s.ID)
		}
	}
	if st.FindingsSoFar != 0 {
		t.Errorf("findings_so_far = %d, want 0", st.FindingsSoFar)
	}
}

// TestRunnerNoProgressKeepsStdoutQuiet verifies that without
// ProgressJSON the runner writes nothing to stdout (historical
// behavior: campaign output is stderr + files only).
func TestRunnerNoProgressKeepsStdoutQuiet(t *testing.T) {
	tp, pp := writeMiniFixture(t)
	tgt, _ := core.LoadTarget(tp)
	pb, err := Load(pp)
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	runner := &Runner{Target: tgt, Playbook: pb, OutDir: filepath.Join(t.TempDir(), "run")}
	if err := runner.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	w.Close()
	os.Stdout = old
	buf := make([]byte, 1)
	if n, _ := r.Read(buf); n != 0 {
		t.Errorf("stdout should be empty without ProgressJSON, got %q", buf)
	}
}
