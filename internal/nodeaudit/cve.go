package nodeaudit

import (
	"context"
	_ "embed"
	"fmt"
	"strconv"
	"strings"

	"github.com/blocktack/blocktack/internal/core"
	"gopkg.in/yaml.v3"
)

//go:embed nodecves.yaml
var cveDBRaw []byte

type cveDB struct {
	Version int          `yaml:"version"`
	Clients []clientEntry `yaml:"clients"`
}

type clientEntry struct {
	Name           string       `yaml:"name"`
	Match          string       `yaml:"match"`
	Vulnerabilities []vulnEntry `yaml:"vulnerabilities"`
}

type vulnEntry struct {
	ID       string `yaml:"id"`
	Summary  string `yaml:"summary"`
	FixedIn  string `yaml:"fixedIn"`
	Reference string `yaml:"reference"`
	Layer    string `yaml:"layer"`
	Weakness string `yaml:"weakness"`
}

func loadCVEDB() (*cveDB, error) {
	var db cveDB
	if err := yaml.Unmarshal(cveDBRaw, &db); err != nil {
		return nil, fmt.Errorf("parse embedded cve db: %w", err)
	}
	return &db, nil
}

// extractVersion parses the semantic version out of a client version
// string, e.g. "Geth/v1.10.7-stable-.../linux-amd64/go1.21.7" -> [1,10,7].
// It scans '/'-separated segments and uses the first that looks like a
// version (v-prefixed, digits after trimming).
func extractVersion(clientVersion string) []int {
	for _, seg := range strings.Split(clientVersion, "/") {
		seg = strings.TrimPrefix(seg, "v")
		if seg == "" || seg[0] < '0' || seg[0] > '9' {
			continue
		}
		if end := strings.IndexAny(seg, "-+ "); end >= 0 {
			seg = seg[:end]
		}
		var out []int
		ok := true
		for _, part := range strings.Split(seg, ".") {
			n, err := strconv.Atoi(part)
			if err != nil {
				ok = false
				break
			}
			out = append(out, n)
		}
		if ok && len(out) > 0 {
			return out
		}
	}
	return nil
}

// versionLess reports whether a is strictly less than b, comparing
// component-wise (missing components count as 0).
func versionLess(a, b []int) bool {
	for i := range b {
		var av int
		if i < len(a) {
			av = a[i]
		}
		if av < b[i] {
			return true
		}
		if av > b[i] {
			return false
		}
	}
	return false
}

func parseFixedIn(s string) []int {
	var out []int
	for _, part := range strings.Split(s, ".") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

// cveCheck fingerprints the node's client via web3_clientVersion and
// cross-references the parsed version against the vulnerability DB.
func cveCheck(ctx context.Context, tgt *core.Target) ([]core.Finding, error) {
	db, err := loadCVEDB()
	if err != nil {
		return nil, err
	}
	var findings []core.Finding
	for _, ep := range rpcEndpoints(tgt) {
		version, err := clientVersion(ctx, ep.URL)
		if err != nil {
			findings = append(findings, core.Finding{
				ID:          "nodeaudit-cve-unreachable",
				Title:       "RPC endpoint unreachable during cve-check",
				Severity:    core.SevInfo,
				Layer:       "L0",
				Description: err.Error(),
			})
			continue
		}
		matched := false
		for _, client := range db.Clients {
			if !strings.Contains(version, client.Match) {
				continue
			}
			matched = true
			parsed := extractVersion(version)
			for _, v := range client.Vulnerabilities {
				fixedIn := parseFixedIn(v.FixedIn)
				if parsed != nil && versionLess(parsed, fixedIn) {
					f := core.Finding{
						ID:         "nodeaudit-" + v.ID,
						Title:      fmt.Sprintf("Node client vulnerable to %s", v.ID),
						Severity:   core.SevHigh,
						Confidence: core.ConfHigh,
						Layer:      orDefault(v.Layer, "L1"),
						Weakness:   v.Weakness,
						Description: fmt.Sprintf(
							"The node runs %s, which is older than the fixed version %s. %s",
							version, v.FixedIn, v.Summary,
						),
						Evidence: fmt.Sprintf("clientVersion=%q fixedIn=%s", version, v.FixedIn),
						PoC:      v.Reference,
					}
					findings = append(findings, f)
				}
			}
		}
		if !matched {
			findings = append(findings, core.Finding{
				ID:       "nodeaudit-cve-no-entry",
				Title:    "Client not in vulnerability database",
				Severity: core.SevInfo,
				Layer:    "L1",
				Weakness: "BTV-L1-001",
				Description: fmt.Sprintf(
					"Client version %q fingerprinted but has no entries in BlockTack's node "+
						"vulnerability database. Manual review of the client's security "+
						"advisories is required.", version),
				Evidence: fmt.Sprintf("clientVersion=%q", version),
			})
		}
	}
	return normalize(findings, "cve-check"), nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
