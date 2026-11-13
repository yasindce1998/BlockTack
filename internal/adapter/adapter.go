// Package adapter bridges BlockTack to external analysis tools (Slither,
// Echidna, Foundry, ...) via Python adapter scripts that speak SARIF.
package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/blocktack/blocktack/internal/core"
)

// Adapter wraps a Python adapter script in adapters/.
type Adapter struct {
	Name   string
	Script string // absolute or repo-relative path to the .py script
}

// Registry returns the known adapters by name. Adapters live in the
// adapters/ directory of the repo and follow the btadapter.py contract:
//   python3 <script> --target-file target.json --options-json '{}' --sarif-out out.sarif
func Registry() map[string]Adapter {
	dir := adaptersDir()
	return map[string]Adapter{
		"slither": {Name: "slither", Script: filepath.Join(dir, "slither_adapter.py")},
	}
}

func adaptersDir() string {
	return filepath.Join(core.RepoRoot(), "adapters")
}

// Names returns the registered adapter names.
func Names() []string {
	reg := Registry()
	names := make([]string, 0, len(reg))
	for n := range reg {
		names = append(names, n)
	}
	return names
}

// Run executes the adapter against the target and converts its SARIF
// output into BlockTack findings. workDir must already exist.
func (a Adapter) Run(ctx context.Context, tgt *core.Target, options map[string]any, workDir string) ([]core.Finding, error) {
	if options == nil {
		options = map[string]any{}
	}
	targetFile := filepath.Join(workDir, "target-"+a.Name+".json")
	if err := tgt.WriteJSON(targetFile); err != nil {
		return nil, fmt.Errorf("adapter %s: %w", a.Name, err)
	}
	sarifFile := filepath.Join(workDir, a.Name+".sarif")
	opts, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, "python3", a.Script,
		"--target-file", targetFile,
		"--options-json", string(opts),
		"--sarif-out", sarifFile,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("adapter %s failed: %w\n%s", a.Name, err, truncate(string(out), 800))
	}

	data, err := os.ReadFile(sarifFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // adapter ran but produced nothing
		}
		return nil, fmt.Errorf("adapter %s: %w", a.Name, err)
	}
	findings, err := core.ParseSARIFResults(data, a.Name)
	if err != nil {
		return nil, fmt.Errorf("adapter %s: %w", a.Name, err)
	}
	return findings, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
