// Package core defines the data model shared by every BlockTack component:
// the target under assessment, the findings every tool produces, and the
// weakness taxonomy that classifies them.
package core

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"time"

	"gopkg.in/yaml.v3"
)

// Target describes a blockchain system under assessment: its chain, live
// endpoints, deployed contracts, off-chain components, and — critically —
// the authorization under which the assessment may run.
type Target struct {
	APIVersion    string        `yaml:"apiVersion" json:"apiVersion"`
	Name          string        `yaml:"name" json:"name"`
	Chain         ChainRef      `yaml:"chain" json:"chain"`
	Endpoints     []Endpoint    `yaml:"endpoints" json:"endpoints"`
	Contracts     []Contract    `yaml:"contracts" json:"contracts"`
	Components    []Component   `yaml:"components" json:"components"`
	Authorization Authorization `yaml:"authorization" json:"authorization"`
}

// ChainRef identifies the chain type and network context of the target.
type ChainRef struct {
	// Type is one of: evm, solana, cosmos, move, bitcoin, permissioned.
	Type    string   `yaml:"type" json:"type"`
	Network string   `yaml:"network" json:"network"` // local | testnet | mainnet | mainnet-fork
	ChainID int64    `yaml:"chainId" json:"chainId"`
	Fork    ForkSpec `yaml:"fork" json:"fork"`
}

// ForkSpec describes a local fork of a live network (e.g. anvil --fork-url).
type ForkSpec struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Base    string `yaml:"base" json:"base"`
	Block   int64  `yaml:"blockNumber" json:"blockNumber"`
}

// Endpoint is a reachable network component of the target.
type Endpoint struct {
	Name string `yaml:"name" json:"name"`
	Role string `yaml:"role" json:"role"` // rpc | p2p | api | indexer | frontend
	URL  string `yaml:"url" json:"url"`
}

// Contract is an on-chain program in scope.
type Contract struct {
	Name     string `yaml:"name" json:"name"`
	Address  string `yaml:"address" json:"address"`
	Verified bool   `yaml:"verified" json:"verified"`
	Source   string `yaml:"sourceDir" json:"sourceDir"` // local path to sources, if available
}

// Component is an off-chain or infrastructure element in scope.
type Component struct {
	Name string `yaml:"name" json:"name"`
	Kind string `yaml:"kind" json:"kind"` // node | bridge | oracle | relayer | indexer | wallet | frontend | custodian
	Note string `yaml:"note" json:"note"`
}

// Authorization declares the rules of engagement for an assessment.
// BlockTack refuses to run against any target without it.
type Authorization struct {
	Declared     bool      `yaml:"declared" json:"declared"`
	AuthorizedBy string    `yaml:"authorizedBy" json:"authorizedBy"`
	Scope        string    `yaml:"scope" json:"scope"`
	Expires      time.Time `yaml:"expires" json:"expires"`
	// LiveTargets lists hostnames that safe mode may contact even though
	// they are not loopback addresses (e.g. a public fork RPC).
	LiveTargets []string `yaml:"liveTargets" json:"liveTargets"`
}

// LoadTarget reads and validates a target YAML file.
func LoadTarget(path string) (*Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read target: %w", err)
	}
	var t Target
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parse target %s: %w", path, err)
	}
	if t.Name == "" {
		return nil, fmt.Errorf("target %s: missing required field `name`", path)
	}
	if t.Chain.Type == "" {
		t.Chain.Type = "evm"
	}
	return &t, nil
}

// WriteJSON serializes the target as JSON for adapters and engines.
func (t *Target) WriteJSON(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(t)
}

// GuardrailError is a refusal raised by BlockTack's authorization and
// safe-mode guardrails. It is typed so callers (CLI, MCP wrappers) can
// distinguish refusals from ordinary failures: the CLI reserves exit
// code 3 for guardrail refusals.
type GuardrailError struct {
	// Code is a stable machine-readable reason:
	//   missing_authorization | missing_expiry | expired_authorization |
	//   unsafe_endpoint
	Code   string
	Target string
	Msg    string
}

func (e *GuardrailError) Error() string { return e.Msg }

// ValidateSafeMode enforces BlockTack's guardrails:
//
//  1. Every target must carry an explicit, unexpired authorization block.
//  2. In safe mode (the default), endpoints must be loopback or explicitly
//     listed in authorization.liveTargets.
//
// Pass safeMode=false only behind an explicit --unsafe flag.
// Refusals are returned as *GuardrailError (stable Code field).
func (t *Target) ValidateSafeMode(safeMode bool) error {
	if !t.Authorization.Declared {
		return &GuardrailError{
			Code:   "missing_authorization",
			Target: t.Name,
			Msg: fmt.Sprintf(
				"target %q has no authorization block: refusing to run. Add\n"+
					"  authorization:\n"+
					"    declared: true\n"+
					"    authorizedBy: <who authorized this assessment>\n"+
					"    scope: <what you are allowed to do>\n"+
					"    expires: <RFC3339 timestamp>\n"+
					"describing your authorization to test this system",
				t.Name,
			),
		}
	}
	if t.Authorization.Expires.IsZero() {
		return &GuardrailError{
			Code:   "missing_expiry",
			Target: t.Name,
			Msg:    fmt.Sprintf("target %q: authorization.expires is required", t.Name),
		}
	}
	if time.Now().After(t.Authorization.Expires) {
		return &GuardrailError{
			Code:   "expired_authorization",
			Target: t.Name,
			Msg: fmt.Sprintf("target %q: authorization expired at %s",
				t.Name, t.Authorization.Expires.Format(time.RFC3339)),
		}
	}
	if !safeMode {
		return nil
	}
	for _, ep := range t.Endpoints {
		u, err := url.Parse(ep.URL)
		if err != nil {
			return fmt.Errorf("target endpoint %s: %w", ep.Name, err)
		}
		host := u.Hostname()
		if host == "" {
			continue
		}
		if hostIsLocal(host) {
			continue
		}
		if slices.Contains(t.Authorization.LiveTargets, host) {
			continue
		}
		return &GuardrailError{
			Code:   "unsafe_endpoint",
			Target: t.Name,
			Msg: fmt.Sprintf(
				"safe mode: endpoint %s (%s) is neither local nor listed in authorization.liveTargets. "+
					"Use a local/forked environment, add the host to authorization.liveTargets, or pass --unsafe if you are authorized",
				ep.Name, host,
			),
		}
	}
	return nil
}

func hostIsLocal(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal":
		return true
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip.IsLoopback() {
			return true
		}
	}
	return false
}

// RepoRoot resolves the repository root: $BLOCKTACK_ROOT if set, else cwd.
// Run commands from the repo root, or export BLOCKTACK_ROOT, so that
// taxonomy/, adapters/ and engine binaries can be located.
func RepoRoot() string {
	if root := os.Getenv("BLOCKTACK_ROOT"); root != "" {
		return root
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

// DefaultTaxonomyPath returns where the weakness taxonomy is expected.
func DefaultTaxonomyPath() string {
	return filepath.Join(RepoRoot(), "taxonomy", "blocktack-matrix.yaml")
}
