// Command blocktack is the CLI for the BlockTack adversary-simulation
// platform for blockchain systems.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blocktack/blocktack/internal/adapter"
	"github.com/blocktack/blocktack/internal/core"
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
		os.Exit(1)
	}
}

func usage(w *os.File) {
	fmt.Fprintf(w, `blocktack %s — end-to-end adversary simulation for blockchain systems

Usage:
  blocktack matrix    [--taxonomy FILE]               print the weakness taxonomy
  blocktack recon     --target FILE [--out FILE]      probe target endpoints (L0/L1)
  blocktack scan      --target FILE [--adapters a,b]  run analysis adapters (Slither, ...)
  blocktack campaign  --target FILE --playbook FILE   execute an attack playbook
  blocktack node-audit --target FILE [--module m]    L0/L1 node attack-surface audit
  blocktack report    --findings a.json,b.json        merge findings into a markdown report

Targets are YAML files (see examples/targets/). Every target must carry an
authorization block; safe mode (default) additionally restricts endpoints to
loopback addresses or authorization.liveTargets.

Run `+"`blocktack <command> --help`"+` for command-specific flags.
`, version)
}

func cmdMatrix(args []string) error {
	fs := flag.NewFlagSet("matrix", flag.ContinueOnError)
	taxPath := fs.String("taxonomy", core.DefaultTaxonomyPath(), "path to taxonomy YAML")
	if err := fs.Parse(args); err != nil {
		return err
	}
	tx, err := core.LoadTaxonomy(*taxPath)
	if err != nil {
		return err
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

func cmdRecon(args []string) error {
	fs := flag.NewFlagSet("recon", flag.ContinueOnError)
	targetPath := fs.String("target", "", "path to target YAML (required)")
	out := fs.String("out", "", "write findings JSON to this file (default: SARIF to stdout)")
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
	return core.WriteSARIF(os.Stdout, findings)
}

func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	targetPath := fs.String("target", "", "path to target YAML (required)")
	adaptersFlag := fs.String("adapters", "slither", "comma-separated adapter names")
	out := fs.String("out", "", "write findings JSON to this file (default: SARIF to stdout)")
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
	return core.WriteSARIF(os.Stdout, findings)
}

func cmdCampaign(args []string) error {
	fs := flag.NewFlagSet("campaign", flag.ContinueOnError)
	targetPath := fs.String("target", "", "path to target YAML (required)")
	playbookPath := fs.String("playbook", "", "path to playbook YAML (required)")
	outBase := fs.String("out-dir", filepath.Join("runs", "campaigns"), "base directory for campaign output")
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
	r := &playbook.Runner{Target: tgt, Playbook: pb, OutDir: outDir, Unsafe: *unsafe}
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
	return core.WriteSARIF(os.Stdout, findings)
}

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	findingsFlag := fs.String("findings", "", "comma-separated findings JSON files (required)")
	out := fs.String("out", "report.md", "output markdown file")
	title := fs.String("title", "BlockTack Assessment Report", "report title")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *findingsFlag == "" {
		return fmt.Errorf("--findings is required")
	}
	var all []core.Finding
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
	}
	f, err := os.Create(*out)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := report.Markdown(f, all, *title); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d findings)\n", *out, len(all))
	return nil
}
