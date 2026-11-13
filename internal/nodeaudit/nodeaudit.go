// Package nodeaudit implements L0/L1 attack-surface modules that run
// against a live node: client-version CVE cross-referencing, malformed
// RPC fuzzing, mempool exposure analysis, and peer-topology analysis.
package nodeaudit

import (
	"context"
	"fmt"

	"github.com/blocktack/blocktack/internal/core"
	"github.com/blocktack/blocktack/internal/webaudit"
)

// Modules returns the available audit module names.
func Modules() []string {
	return []string{"cve-check", "rpc-fuzz", "mempool-analysis", "peer-analysis"}
}

// Run executes one module (or "all") against the target's RPC endpoints
// and returns findings. Every module is read-only or sends only
// deliberately malformed RPC input; none broadcasts transactions.
func Run(ctx context.Context, module string, tgt *core.Target) ([]core.Finding, error) {
	var findings []core.Finding
	var err error
	switch module {
	case "all":
		for _, m := range Modules() {
			fs, err := runModule(ctx, m, tgt)
			if err != nil {
				return findings, fmt.Errorf("module %s: %w", m, err)
			}
			findings = append(findings, fs...)
		}
		return findings, nil
	default:
		findings, err = runModule(ctx, module, tgt)
		if err != nil {
			return nil, fmt.Errorf("module %s: %w", module, err)
		}
		return findings, nil
	}
}

func runModule(ctx context.Context, module string, tgt *core.Target) ([]core.Finding, error) {
	switch module {
	case "cve-check":
		return cveCheck(ctx, tgt)
	case "rpc-fuzz":
		return rpcFuzz(ctx, tgt)
	case "mempool-analysis":
		return mempoolAnalysis(ctx, tgt)
	case "peer-analysis":
		return peerAnalysis(ctx, tgt)
	case "web-audit":
		return webaudit.Run(ctx, tgt)
	default:
		return nil, fmt.Errorf("unknown module %q (available: %v, web-audit, all)", module, Modules())
	}
}

func normalize(fs []core.Finding, source string) []core.Finding {
	for i := range fs {
		fs[i].Normalize()
		if fs[i].Source == "" {
			fs[i].Source = source
		}
	}
	return fs
}
