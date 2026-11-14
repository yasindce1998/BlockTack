// Command blocktack is the CLI for the BlockTack adversary-simulation
// platform for blockchain systems.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blocktack/blocktack/internal/adapter"
	"github.com/blocktack/blocktack/internal/core"
	"github.com/blocktack/blocktack/internal/correlate"
	"github.com/blocktack/blocktack/internal/nodeaudit"
	"github.com/blocktack/blocktack/internal/playbook"
	"github.com/blocktack/blocktack/internal/recon"
	"github.com/blocktack/blocktack/internal/report"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Println("blocktack " + version)
	case "matrix":
		err = cmdMatrix(os.Args[2:])
	case "capabilities":
		err = cmdCapabilities(os.Args[2:])
	case "validate-target":
		err = cmdValidateTarget(os.Args[2:])
	case "recon":
		err = cmdRecon(os.Args[2:])
	case "scan":
		err = cmdScan(os.Args[2:])
	case "campaign":
		err = cmdCampaign(os.Args[2:])
	case "node-audit":
		err = cmdNodeAudit(os.Args[2:])
	case "report":
		err = cmdReport(os.Args[2:])
	case "help", "--help", "-h":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		if jsonErrors() {
			emitErrorObject(err)
		}
		var gr *core.GuardrailError
		if errors.As(err, &gr) {
			// Exit code 3 is reserved for guardrail refusals so
			// machine callers (MCP wrappers, CI) never confuse a
			// refusal with an operational failure.
			os.Exit(3)
		}
		os.Exit(1)
	}
}

// jsonErrors reports whether structured error objects should be printed
// to stderr (BLOCKTACK_JSON_ERRORS=1 — convenient for processes whose
// stderr is consumed by a tool wrapper).
func jsonErrors() bool {
	return os.Getenv("BLOCKTACK_JSON_ERRORS") == "1"
}

// emitErrorObject writes one structured error object to stderr:
// {"error":{"code":"...","message":"...","target":"..."}}.
func emitErrorObject(err error) {
	obj := map[string]any{"message": err.Error()}
	var gr *core.GuardrailError
	if errors.As(err, &gr) {
		obj["code"] = gr.Code
		obj["guardrail"] = true
		if gr.Target != "" {
			obj["target"] = gr.Target
		}
	} else {
		obj["code"] = "internal_error"
	}
	data, merr := json.Marshal(map[string]any{"error": obj})
	if merr != nil {
		return
	}
	fmt.Fprintln(os.Stderr, string(data))
}

func usage(w *os.File) {
	fmt.Fprintf(w, `blocktack %s — end-to-end adversary simulation for blockchain systems

Usage:
  blocktack matrix    [--taxonomy FILE] [--json]        print the weakness taxonomy
  blocktack capabilities                              machine-readable platform inventory
                                                      (commands, engines, adapters, taxonomy)
  blocktack validate-target --target FILE             dry-validate a target: authorization
                                                      block + safe-mode verdict as JSON, no
                                                      endpoint contact
  blocktack recon     --target FILE [--out FILE]      probe target endpoints (L0/L1)
                      [--emit sarif|findings-json]
  blocktack scan      --target FILE [--adapters a,b]  run analysis adapters (Slither, ...)
                      [--emit sarif|findings-json]
  blocktack campaign  --target FILE --playbook FILE   execute an attack playbook
                      [--progress-json]               JSON-lines progress on stdout +
                                                      crash-resilient status.json per step
  blocktack node-audit --target FILE [--module m]    L0/L1 node attack-surface audit
                      [--emit sarif|findings-json]
  blocktack report    --findings a.json,b.json        merge findings into a markdown report
                      [--engagement]                  engagement-grade deliverable (exec
                                                      summary, kill chains, remediation)
                      [--target FILE] [--killchains FILE] engagement context (optional)

Targets are YAML files (see examples/targets/). Every target must carry an
authorization block; safe mode (default) additionally restricts endpoints to
loopback addresses or authorization.liveTargets. Guardrail refusals exit with
code 3; set BLOCKTACK_JSON_ERRORS=1 for structured error objects on stderr.

Run `+"`blocktack <command> --help`"+` for command-specific flags.
`, version)
}

func cmdMatrix(args []string) error {
	fs := flag.NewFlagSet("matrix", flag.ContinueOnError)
	taxPath := fs.String("taxonomy", core.DefaultTaxonomyPath(), "path to taxonomy YAML")
	asJSON := fs.Bool("json", false, "emit the taxonomy as JSON (machine-readable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	tx, err := core.LoadTaxonomy(*taxPath)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(tx)
	}
	total := 0
	fmt.Printf("BlockTack weakness taxonomy v%d — %d layers\n\n", tx.Version, len(tx.Layers))
	for _, l := range tx.Layers {
		total += len(l.Weaknesses)
		fmt.Printf("%s  %s — %d weaknesses\n", l.ID, l.Name, len(l.Weaknesses))
		for _, w := range l.Weaknesses {
			fmt.Printf("    %-13s %s\n", w.ID, w.Name)
		}
		fmt.Println()
	}
	fmt.Printf("total: %d weaknesses\n", total)
	return nil
}

// cmdCapabilities prints a machine-readable inventory of the platform:
// commands, engines (probed on disk), adapters, nodeaudit modules, and
// the taxonomy summary. Read-only, no target needed — the entry point
// for AI planners to discover what they can drive.
func cmdCapabilities(args []string) error {
	fs := flag.NewFlagSet("capabilities", flag.ContinueOnError)
	taxPath := fs.String("taxonomy", core.DefaultTaxonomyPath(), "path to taxonomy YAML")
	if err := fs.Parse(args); err != nil {
		return err
	}
	caps := map[string]any{
		"version":  version,
		"root":     core.RepoRoot(),
		"commands": []string{"matrix", "recon", "scan", "campaign", "node-audit", "report", "validate-target", "capabilities"},
		"adapters": adapter.Names(),
		"nodeaudit_modules": []string{
			"all", "cve-check", "rpc-fuzz", "mempool-analysis", "peer-analysis", "web-audit", "p2p-eclipse",
		},
	}
	engines := []map[string]any{}
	for _, name := range []string{"blocktack-evm", "blocktack-solana"} {
		path := enginePathFor(name)
		entry := map[string]any{"name": name, "present": false}
		if st, err := os.Stat(path); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			entry["present"] = true
			entry["path"] = path
		}
		engines = append(engines, entry)
	}
	caps["engines"] = engines
	if tx, err := core.LoadTaxonomy(*taxPath); err == nil {
		weaknesses := 0
		layers := []map[string]any{}
		for _, l := range tx.Layers {
			weaknesses += len(l.Weaknesses)
			layers = append(layers, map[string]any{
				"id": l.ID, "name": l.Name, "weaknesses": len(l.Weaknesses),
			})
		}
		caps["taxonomy"] = map[string]any{
			"version":    tx.Version,
			"layers":     layers,
			"weaknesses": weaknesses,
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(caps)
}

// enginePathFor mirrors playbook engine resolution for presence probing.
func enginePathFor(name string) string {
	if dir := os.Getenv("BLOCKTACK_ENGINES"); dir != "" {
		return filepath.Join(dir, name)
	}
	dir := "engine-" + strings.TrimPrefix(name, "blocktack-")
	return filepath.Join(core.RepoRoot(), dir, "target", "release", name)
}

// cmdValidateTarget dry-validates a target file: YAML parse plus
// guardrail enforcement, zero side effects (no endpoint contact). The
// verdict includes the resolved endpoint list so callers (e.g. MCP
// wrappers) can feed engagement scope checks.
func cmdValidateTarget(args []string) error {
	fs := flag.NewFlagSet("validate-target", flag.ContinueOnError)
	targetPath := fs.String("target", "", "path to target YAML (required)")
	unsafe := fs.Bool("unsafe", false, "skip the safe-mode endpoint restriction (authorization block still required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *targetPath == "" {
		return fmt.Errorf("--target is required")
	}
	verdict := map[string]any{"valid": false, "target": *targetPath}
	tgt, err := core.LoadTarget(*targetPath)
	if err != nil {
		verdict["error"] = err.Error()
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(verdict)
		return err
	}
	var violations []string
	var refusal error
	if err := tgt.ValidateSafeMode(!*unsafe); err != nil {
		verdict["error"] = err.Error()
		var gr *core.GuardrailError
		if errors.As(err, &gr) {
			verdict["guardrail"] = gr.Code
			refusal = err // propagate so the CLI exits 3 on guardrail refusals
		}
		violations = append(violations, err.Error())
	}
	endpoints := []map[string]any{}
	for _, ep := range tgt.Endpoints {
		endpoints = append(endpoints, map[string]any{
			"role": ep.Role,
			"name": ep.Name,
			"url":  ep.URL,
		})
	}
	verdict["valid"] = len(violations) == 0
	verdict["name"] = tgt.Name
	verdict["chain"] = tgt.Chain
	verdict["endpoints"] = endpoints
	if tgt.Authorization.Declared {
		verdict["authorization"] = map[string]any{
			"declared":      true,
			"authorized_by": tgt.Authorization.AuthorizedBy,
			"scope":         tgt.Authorization.Scope,
			"expires":       tgt.Authorization.Expires.Format(time.RFC3339),
			"live_targets":  tgt.Authorization.LiveTargets,
		}
	}
	if len(violations) > 0 {
		verdict["violations"] = violations
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(verdict); err != nil {
		return err
	}
	if refusal != nil {
		return refusal
	}
	if len(violations) > 0 {
		return errors.New(strings.Join(violations, "; "))
	}
	return nil
}

func cmdRecon(args []string) error {
	fs := flag.NewFlagSet("recon", flag.ContinueOnError)
	targetPath := fs.String("target", "", "path to target YAML (required)")
	out := fs.String("out", "", "write findings JSON to this file (default: SARIF to stdout)")
	emit := fs.String("emit", "sarif", "stdout format when --out is not set: sarif | findings-json")
	unsafe := fs.Bool("unsafe", false, "allow non-local endpoints (still requires authorization)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *targetPath == "" {
		return fmt.Errorf("--target is required")
	}
	tgt, err := core.LoadTarget(*targetPath)
	if err != nil {
		return err
	}
	if err := tgt.ValidateSafeMode(!*unsafe); err != nil {
		return err
	}
	findings := recon.Run(context.Background(), tgt)
	fmt.Fprintf(os.Stderr, "recon complete: %d findings\n", len(findings))
	if *out != "" {
		return core.SaveFindingsJSON(findings, *out)
	}
	return emitFindings(os.Stdout, findings, *emit)
}

func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	targetPath := fs.String("target", "", "path to target YAML (required)")
	adaptersFlag := fs.String("adapters", "slither", "comma-separated adapter names")
	out := fs.String("out", "", "write findings JSON to this file (default: SARIF to stdout)")
	emit := fs.String("emit", "sarif", "stdout format when --out is not set: sarif | findings-json")
	unsafe := fs.Bool("unsafe", false, "allow non-local endpoints (still requires authorization)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *targetPath == "" {
		return fmt.Errorf("--target is required")
	}
	tgt, err := core.LoadTarget(*targetPath)
	if err != nil {
		return err
	}
	if err := tgt.ValidateSafeMode(!*unsafe); err != nil {
		return err
	}
	workDir, err := os.MkdirTemp("", "blocktack-scan-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)

	reg := adapter.Registry()
	var findings []core.Finding
	for _, name := range strings.Split(*adaptersFlag, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		a, ok := reg[name]
		if !ok {
			return fmt.Errorf("unknown adapter %q (available: %v)", name, adapter.Names())
		}
		fs, err := a.Run(context.Background(), tgt, nil, workDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
			continue
		}
		findings = append(findings, fs...)
		fmt.Fprintf(os.Stderr, "adapter %s: %d findings\n", name, len(fs))
	}
	if *out != "" {
		return core.SaveFindingsJSON(findings, *out)
	}
	return emitFindings(os.Stdout, findings, *emit)
}

func cmdCampaign(args []string) error {
	fs := flag.NewFlagSet("campaign", flag.ContinueOnError)
	targetPath := fs.String("target", "", "path to target YAML (required)")
	playbookPath := fs.String("playbook", "", "path to playbook YAML (required)")
	outBase := fs.String("out-dir", filepath.Join("runs", "campaigns"), "base directory for campaign output")
	progressJSON := fs.Bool("progress-json", false, "emit JSON-lines progress events to stdout (machine-readable campaign channel)")
	unsafe := fs.Bool("unsafe", false, "allow non-local endpoints (still requires authorization)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *targetPath == "" {
		return fmt.Errorf("--target is required")
	}
	if *playbookPath == "" {
		return fmt.Errorf("--playbook is required")
	}
	tgt, err := core.LoadTarget(*targetPath)
	if err != nil {
		return err
	}
	pb, err := playbook.Load(*playbookPath)
	if err != nil {
		return err
	}
	outDir := filepath.Join(*outBase,
		time.Now().UTC().Format("20060102-150405")+"-"+playbook.SanitizeName(pb.Name))
	r := &playbook.Runner{
		Target:       tgt,
		Playbook:     pb,
		OutDir:       outDir,
		Unsafe:       *unsafe,
		ProgressJSON: *progressJSON,
	}
	if err := r.Run(context.Background()); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\ncampaign output: %s\n", outDir)
	return nil
}

func cmdNodeAudit(args []string) error {
	fs := flag.NewFlagSet("node-audit", flag.ContinueOnError)
	targetPath := fs.String("target", "", "path to target YAML (required)")
	module := fs.String("module", "all", "audit module: all, cve-check, rpc-fuzz, mempool-analysis, peer-analysis")
	out := fs.String("out", "", "write findings JSON to this file (default: SARIF to stdout)")
	emit := fs.String("emit", "sarif", "stdout format when --out is not set: sarif | findings-json")
	unsafe := fs.Bool("unsafe", false, "allow non-local endpoints (still requires authorization)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *targetPath == "" {
		return fmt.Errorf("--target is required")
	}
	tgt, err := core.LoadTarget(*targetPath)
	if err != nil {
		return err
	}
	if err := tgt.ValidateSafeMode(!*unsafe); err != nil {
		return err
	}
	findings, err := nodeaudit.Run(context.Background(), *module, tgt)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "node-audit (%s): %d findings\n", *module, len(findings))
	if *out != "" {
		return core.SaveFindingsJSON(findings, *out)
	}
	return emitFindings(os.Stdout, findings, *emit)
}

// emitFindings writes findings to w in the requested format. Default
// remains SARIF (byte-identical behavior); "findings-json" emits the
// native findings array for machine callers.
func emitFindings(w *os.File, findings []core.Finding, format string) error {
	switch format {
	case "", "sarif":
		return core.WriteSARIF(w, findings)
	case "findings-json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(findings)
	default:
		return fmt.Errorf("unknown --emit format %q (want sarif or findings-json)", format)
	}
}

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	findingsFlag := fs.String("findings", "", "comma-separated findings JSON files (required)")
	out := fs.String("out", "report.md", "output markdown file")
	title := fs.String("title", "BlockTack Assessment Report", "report title")
	engagement := fs.Bool("engagement", false, "render an engagement-grade deliverable (executive summary, kill chains, remediation guidance)")
	targetPath := fs.String("target", "", "path to target YAML (engagement mode: authorization and scope context)")
	killchainsPath := fs.String("killchains", "", "path to killchains.json (engagement mode)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *findingsFlag == "" {
		return fmt.Errorf("--findings is required")
	}
	var all []core.Finding
	var files []string
	for _, path := range strings.Split(*findingsFlag, ",") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		fs, err := core.LoadFindingsJSON(path)
		if err != nil {
			return err
		}
		all = append(all, fs...)
		files = append(files, path)
	}
	f, err := os.Create(*out)
	if err != nil {
		return err
	}
	defer f.Close()
	if !*engagement {
		if err := report.Markdown(f, all, *title); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %s (%d findings)\n", *out, len(all))
		return nil
	}

	// Engagement mode: pull authorization/scope context and kill chains.
	var tgt *core.Target
	if *targetPath != "" {
		tgt, err = core.LoadTarget(*targetPath)
		if err != nil {
			return err
		}
	}
	var chains []correlate.KillChain
	if *killchainsPath != "" {
		chains, err = loadKillChains(*killchainsPath)
		if err != nil {
			return err
		}
	}
	titleSet := false
	fs.Visit(func(fl *flag.Flag) {
		if fl.Name == "title" {
			titleSet = true
		}
	})
	if !titleSet {
		*title = "BlockTack Engagement Report"
	}
	opts := report.EngagementOptions{
		Title:         *title,
		ToolVersion:   version,
		Target:        tgt,
		TaxonomyPath:  core.DefaultTaxonomyPath(),
		FindingsFiles: files,
		SarifPath:     siblingSarif(files),
	}
	if err := report.EngagementMarkdown(f, all, chains, opts); err != nil {
		return err
	}
	chainMsg := ""
	if len(chains) == 1 {
		chainMsg = ", 1 kill chain"
	} else if len(chains) > 1 {
		chainMsg = fmt.Sprintf(", %d kill chains", len(chains))
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d findings%s)\n", *out, len(all), chainMsg)
	return nil
}

// loadKillChains reads a killchains.json produced by a campaign run.
func loadKillChains(path string) ([]correlate.KillChain, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read killchains: %w", err)
	}
	var chains []correlate.KillChain
	if err := json.Unmarshal(data, &chains); err != nil {
		return nil, fmt.Errorf("parse killchains %s: %w", path, err)
	}
	return chains, nil
}

// siblingSarif returns the findings.sarif that campaigns write next to a
// findings.json, if one exists; empty string otherwise.
func siblingSarif(files []string) string {
	if len(files) == 0 || filepath.Ext(files[0]) != ".json" {
		return ""
	}
	candidate := strings.TrimSuffix(files[0], ".json")
	if filepath.Base(candidate) == "findings" {
		candidate += ".sarif"
	} else {
		candidate = filepath.Join(filepath.Dir(files[0]), "findings.sarif")
	}
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return ""
}
