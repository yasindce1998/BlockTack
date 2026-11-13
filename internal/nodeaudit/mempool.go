package nodeaudit

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/blocktack/blocktack/internal/core"
)

// txpoolContent models the txpool_content response shape.
type txpoolContent struct {
	Pending map[string]map[string]txDetail `json:"pending"`
	Queued  map[string]map[string]txDetail `json:"queued"`
}

type txDetail struct {
	To   string `json:"to"`
	Hash string `json:"hash"`
}

// mempoolAnalysis checks whether the node's mempool is readable
// (BTV-L1-009) and summarizes what an attacker can see and front-run.
func mempoolAnalysis(ctx context.Context, tgt *core.Target) ([]core.Finding, error) {
	var findings []core.Finding
	for _, ep := range rpcEndpoints(tgt) {
		res, err := rpcCall(ctx, ep.URL, "txpool_content", []any{})
		if err != nil {
			findings = append(findings, core.Finding{
				ID:       "nodeaudit-mempool-closed",
				Title:    "Mempool not exposed",
				Severity: core.SevInfo,
				Layer:    "L0",
				Description: "txpool_content was rejected — pending transactions are not " +
					"readable from this endpoint (good).",
				Target: ep.Name,
			})
			continue
		}
		var content txpoolContent
		if err := json.Unmarshal(res, &content); err != nil {
			findings = append(findings, core.Finding{
				ID:          "nodeaudit-mempool-parse",
				Title:       "Could not parse txpool_content response",
				Severity:    core.SevInfo,
				Layer:       "L0",
				Description: err.Error(),
				Target:      ep.Name,
			})
			continue
		}
		pending := 0
		var sample []string
		for _, byNonce := range content.Pending {
			for _, tx := range byNonce {
				pending++
				if len(sample) < 5 {
					sample = append(sample, tx.Hash)
				}
			}
		}
		if pending == 0 {
			findings = append(findings, core.Finding{
				ID:       "nodeaudit-mempool-empty",
				Title:    "Mempool exposed but empty",
				Severity: core.SevLow,
				Layer:    "L0",
				Weakness: "BTV-L0-001",
				Description: "txpool_content is readable (pending transactions are visible " +
					"to unauthenticated callers); the pool is currently empty.",
				Target: ep.Name,
			})
			continue
		}
		findings = append(findings, core.Finding{
			ID:         "nodeaudit-mempool-exposed",
			Title:      fmt.Sprintf("Mempool exposed: %d pending transactions visible", pending),
			Severity:   core.SevMedium,
			Confidence: core.ConfConfirmed,
			Layer:      "L1",
			Weakness:   "BTV-L1-009",
			Description: fmt.Sprintf(
				"Pending transactions are readable via txpool_content. Every one of them is "+
					"a front-running/sandwich target (BTV-L5-004): an attacker watching this "+
					"endpoint can order around them. Sample: %v", sample),
			Target: ep.Name,
		})
	}
	return normalize(findings, "mempool-analysis"), nil
}

// adminPeers models one entry of the admin_peers response.
type adminPeer struct {
	Enode     string `json:"enode"`
	Name      string `json:"name"`
	Caps      []string `json:"caps"`
	Network   struct {
		RemoteAddress string `json:"remoteAddress"`
	} `json:"network"`
}

// peerAnalysis reads the node's peer topology (if the admin namespace
// is exposed) and computes eclipse-susceptibility heuristics.
func peerAnalysis(ctx context.Context, tgt *core.Target) ([]core.Finding, error) {
	var findings []core.Finding
	for _, ep := range rpcEndpoints(tgt) {
		res, err := rpcCall(ctx, ep.URL, "admin_peers", []any{})
		if err != nil {
			findings = append(findings, core.Finding{
				ID:       "nodeaudit-peers-closed",
				Title:    "Peer list not exposed",
				Severity: core.SevInfo,
				Layer:    "L0",
				Description: "admin_peers was rejected — the node's p2p topology is not " +
					"disclosed to unauthenticated callers (good).",
				Target: ep.Name,
			})
			continue
		}
		var peers []adminPeer
		if err := json.Unmarshal(res, &peers); err != nil {
			findings = append(findings, core.Finding{
				ID:          "nodeaudit-peers-parse",
				Title:       "Could not parse admin_peers response",
				Severity:    core.SevInfo,
				Layer:       "L0",
				Description: err.Error(),
				Target:      ep.Name,
			})
			continue
		}

		// Heuristics: peer count and network concentration.
		subnets := map[string]int{}
		clients := map[string]int{}
		for _, p := range peers {
			clients[p.Name]++
			host := p.Network.RemoteAddress
			for i := 0; i < len(host); i++ {
				if host[i] == ':' {
					host = host[:i]
					break
				}
			}
			parts := splitDots(host)
			if len(parts) == 4 {
				subnets[parts[0]+"."+parts[1]+"."+parts[2]]++
			} else if len(parts) > 0 {
				subnets[parts[0]]++
			}
		}
		maxSubnet := 0
		for _, n := range subnets {
			if n > maxSubnet {
				maxSubnet = n
			}
		}
		findings = append(findings, core.Finding{
			ID:         "nodeaudit-peers-exposed",
			Title:      fmt.Sprintf("Peer topology exposed: %d peers", len(peers)),
			Severity:   core.SevMedium,
			Confidence: core.ConfConfirmed,
			Layer:      "L0",
			Weakness:   "BTV-L0-002",
			Description: fmt.Sprintf(
				"admin_peers discloses the node's p2p topology (%d peers, %d distinct client "+
					"strings). This is the recon an eclipse attack (BTV-L1-002) needs: peer "+
					"replacement becomes plannable.", len(peers), len(clients)),
			Evidence: fmt.Sprintf("peers=%d distinct_client_strings=%d max_same_subnet=%d",
				len(peers), len(clients), maxSubnet),
			Target: ep.Name,
		})
		if len(peers) > 0 && maxSubnet*2 >= len(peers) && len(peers) >= 4 {
			findings = append(findings, core.Finding{
				ID:       "nodeaudit-eclipse-risk",
				Title:    "Peer concentration suggests eclipse susceptibility",
				Severity: core.SevMedium,
				Layer:    "L1",
				Weakness: "BTV-L1-002",
				Description: fmt.Sprintf(
					"%d of %d peers share a single subnet — a single network operator is "+
						"positioned to replace most of this node's view of the network.",
					maxSubnet, len(peers)),
				Evidence: fmt.Sprintf("max_same_subnet=%d peers=%d", maxSubnet, len(peers)),
				Target:   ep.Name,
			})
		}
	}
	return normalize(findings, "peer-analysis"), nil
}

func splitDots(host string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(host); i++ {
		if i == len(host) || host[i] == '.' {
			out = append(out, host[start:i])
			start = i + 1
		}
	}
	return out
}
