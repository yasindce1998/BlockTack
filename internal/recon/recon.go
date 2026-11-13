// Package recon performs target-safe reconnaissance against blockchain
// infrastructure: RPC identity probing and privileged-namespace exposure
// checks (layers L0/L1).
package recon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/blocktack/blocktack/internal/core"
)

type rpcProbe struct {
	method   string
	weakness string
	severity core.Severity
	title    string
	why      string
}

// privilegedProbes are non-destructive RPC calls that should never succeed
// against a hardened node. Success means the namespace is exposed.
var privilegedProbes = []rpcProbe{
	{
		method:   "admin_nodeInfo",
		weakness: "BTV-L0-002",
		severity: core.SevMedium,
		title:    "Node admin namespace exposed",
		why:      "admin_nodeInfo discloses client identity, ENR and configuration details to unauthenticated callers",
	},
	{
		method:   "admin_peers",
		weakness: "BTV-L0-002",
		severity: core.SevMedium,
		title:    "Peer list exposed via admin namespace",
		why:      "admin_peers reveals the node's peer topology, aiding eclipse attack planning",
	},
	{
		method:   "txpool_status",
		weakness: "BTV-L0-001",
		severity: core.SevLow,
		title:    "Mempool exposed via txpool namespace",
		why:      "txpool visibility enables mempool sniping and front-running of pending transactions",
	},
	{
		method:   "eth_accounts",
		weakness: "BTV-L0-003",
		severity: core.SevHigh,
		title:    "Node-controlled accounts exposed",
		why:      "eth_accounts succeeding on a public endpoint indicates the node holds unlocked keys (validator, signer, or hot wallet)",
	},
	{
		method:   "personal_listAccounts",
		weakness: "BTV-L0-003",
		severity: core.SevCritical,
		title:    "Keystore reachable via personal namespace",
		why:      "the personal namespace implies the node's keystore is loaded; combined with personal_sign or send helpers this is direct key abuse",
	},
}

// Run probes every RPC endpoint of the target and returns findings.
// All probes are read-only.
func Run(ctx context.Context, tgt *core.Target) []core.Finding {
	client := &http.Client{Timeout: 10 * time.Second}
	var findings []core.Finding
	for _, ep := range tgt.Endpoints {
		if ep.Role != "" && ep.Role != "rpc" {
			continue
		}
		findings = append(findings, probeEndpoint(ctx, client, tgt.Name, ep)...)
	}
	return findings
}

func probeEndpoint(ctx context.Context, client *http.Client, targetName string, ep core.Endpoint) []core.Finding {
	var findings []core.Finding
	add := func(f core.Finding) {
		f.Normalize()
		if f.Source == "" {
			f.Source = "recon"
		}
		if f.Target == "" {
			f.Target = ep.Name + " (" + ep.URL + ")"
		}
		findings = append(findings, f)
	}

	// Identity probes.
	clientVersion, err := call(ctx, client, ep.URL, "web3_clientVersion", nil)
	if err != nil {
		add(core.Finding{
			ID:          "recon-rpc-unreachable",
			Title:       "RPC endpoint unreachable",
			Severity:    core.SevInfo,
			Confidence:  core.ConfHigh,
			Layer:       "L0",
			Description: fmt.Sprintf("endpoint did not answer a JSON-RPC call: %v", err),
		})
		return findings
	}
	add(core.Finding{
		ID:         "recon-client-fingerprint",
		Title:      "Node client fingerprinted",
		Severity:   core.SevInfo,
		Confidence: core.ConfConfirmed,
		Layer:      "L1",
		Weakness:   "BTV-L1-001",
		Description: "web3_clientVersion discloses the client software and version. " +
			"Cross-reference with known client CVEs before attacking protocol handlers.",
		Evidence: truncate(string(clientVersion), 300),
	})

	chainID, err := call(ctx, client, ep.URL, "eth_chainId", nil)
	if err == nil {
		add(core.Finding{
			ID:         "recon-chain-id",
			Title:      "Chain ID discovered",
			Severity:   core.SevInfo,
			Confidence: core.ConfConfirmed,
			Layer:      "L0",
			Description: "eth_chainId succeeded; confirms a live EVM JSON-RPC endpoint. " +
				"Verify it matches the target's declared chainId.",
			Evidence: truncate(string(chainID), 300),
		})
	}

	// Privileged namespace probes: a successful call is the finding.
	for _, p := range privilegedProbes {
		res, err := call(ctx, client, ep.URL, p.method, []any{})
		if err != nil {
			continue // method rejected/unavailable: good
		}
		add(core.Finding{
			ID:          "recon-" + p.method,
			Title:       p.title,
			Severity:    p.severity,
			Confidence:  core.ConfConfirmed,
			Layer:       "L0",
			Weakness:    p.weakness,
			Description: p.why,
			Evidence:    truncate(string(res), 300),
			PoC:         fmt.Sprintf("cast rpc %s --rpc-url %s", p.method, ep.URL),
		})
	}
	return findings
}

// call performs a JSON-RPC POST and returns the raw result, or an error
// covering transport failures and JSON-RPC error responses.
func call(ctx context.Context, client *http.Client, url, method string, params []any) (json.RawMessage, error) {
	if params == nil {
		params = []any{}
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response (HTTP %d): %w", resp.StatusCode, err)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", out.Error.Code, out.Error.Message)
	}
	return out.Result, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
