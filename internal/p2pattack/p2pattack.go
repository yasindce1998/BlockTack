// Package p2pattack verifies the post-exploitation state of a devp2p
// eclipse attack: after attacker-controlled nodes have been dialed into
// a victim (see playbooks/evm/p2p-eclipse.yaml), it reads the victim's
// peer table and reports whether the attacker now owns the victim's
// entire view of the network.
//
// This goes beyond nodeaudit's read-only peer-analysis heuristics: an
// eclipse "execution" module confirms that peer slots are actually held
// by the attacker, which is what enables transaction censorship,
// information cleansing, and 51%-style view replacement on the victim.
package p2pattack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/blocktack/blocktack/internal/core"
)

var rpcClient = &http.Client{Timeout: 15 * time.Second}

// Run queries the target's RPC endpoint(s) for admin_peers and grades
// the eclipse state of the node. It has the same signature as the
// nodeaudit modules and is dispatched via the "p2p-eclipse" builtin.
func Run(ctx context.Context, tgt *core.Target) ([]core.Finding, error) {
	var findings []core.Finding
	for _, ep := range rpcEndpoints(tgt) {
		findings = append(findings, assessEndpoint(ctx, ep)...)
	}
	for i := range findings {
		findings[i].Normalize()
	}
	return findings, nil
}

// adminPeer models the subset of an admin_peers entry we grade on.
type adminPeer struct {
	Enode   string `json:"enode"`
	Name    string `json:"name"`
	Network struct {
		RemoteAddress string `json:"remoteAddress"`
		LocalAddress  string `json:"localAddress"`
		Inbound       bool   `json:"inbound"`
	} `json:"network"`
}

// peerStats summarizes the network concentration of a peer set.
type peerStats struct {
	Total       int      // connected peers
	DistinctIPs int      // distinct remote IPs behind those peers
	MaxPerIP    int      // largest number of peers sharing one IP
	MaxIP       string   // the dominant IP
	Fraction    float64  // MaxPerIP / Total (0 when Total == 0)
	IPs         []string // distinct IPs, for evidence
}

// parseAdminPeers decodes an admin_peers result payload.
func parseAdminPeers(raw []byte) ([]adminPeer, error) {
	var peers []adminPeer
	if err := json.Unmarshal(raw, &peers); err != nil {
		return nil, err
	}
	return peers, nil
}

// hostOf strips the port from a remote address like "10.0.0.7:52642"
// or "[::1]:52642", returning the bare IP.
func hostOf(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// analyzePeers computes eclipse-relevant concentration metrics.
func analyzePeers(peers []adminPeer) peerStats {
	byIP := map[string]int{}
	var ips []string
	for _, p := range peers {
		ip := hostOf(p.Network.RemoteAddress)
		if ip == "" {
			ip = "unknown"
		}
		if _, seen := byIP[ip]; !seen {
			ips = append(ips, ip)
		}
		byIP[ip]++
	}
	s := peerStats{Total: len(peers), DistinctIPs: len(ips), IPs: ips}
	for ip, n := range byIP {
		if n > s.MaxPerIP || (n == s.MaxPerIP && ip < s.MaxIP) {
			s.MaxPerIP = n
			s.MaxIP = ip
		}
	}
	if s.Total > 0 {
		s.Fraction = float64(s.MaxPerIP) / float64(s.Total)
	}
	return s
}

// assessEndpoint grades one RPC endpoint and returns findings.
func assessEndpoint(ctx context.Context, ep core.Endpoint) []core.Finding {
	peers, err := fetchPeers(ctx, ep.URL)
	if err != nil {
		return []core.Finding{{
			ID:          "p2peclipse-unreachable",
			Title:       "Eclipse state not verifiable: admin_peers unavailable",
			Severity:    core.SevInfo,
			Layer:       "L1",
			Description: fmt.Sprintf("admin_peers could not be read from this endpoint (%s), so the eclipse state cannot be confirmed.", err),
			Target:      ep.Name,
			Source:      "p2p-eclipse",
		}}
	}

	stats := analyzePeers(peers)
	return gradeEndpoint(ep, stats)
}

// gradeEndpoint turns computed stats into findings. Split from
// assessEndpoint so tests can exercise the grading thresholds without
// a live node.
func gradeEndpoint(ep core.Endpoint, stats peerStats) []core.Finding {
	evidence := fmt.Sprintf(
		"peers=%d distinct_ips=%d max_per_ip=%d dominant_ip=%s fraction=%.2f ips=%s",
		stats.Total, stats.DistinctIPs, stats.MaxPerIP, stats.MaxIP, stats.Fraction,
		strings.Join(stats.IPs, ","))

	switch {
	case stats.Total == 0:
		return []core.Finding{{
			ID:       "p2peclipse-no-peers",
			Title:    "No peers connected",
			Severity: core.SevInfo,
			Layer:    "L1",
			Description: "The node currently has no devp2p peers. The eclipse state " +
				"cannot be graded (an isolated node is trivially eclipsed, but there is " +
				"no attacker-controlled peer set to measure).",
			Evidence: evidence,
			Target:   ep.Name,
			Source:   "p2p-eclipse",
		}}

	case stats.Fraction >= 0.9 && stats.Total >= 3:
		return []core.Finding{{
			ID:         "p2peclipse-executed",
			Title:      fmt.Sprintf("Eclipse executed: all peer slots attacker-controlled (%d/%d from %s)", stats.MaxPerIP, stats.Total, stats.MaxIP),
			Severity:   core.SevCritical,
			Confidence: core.ConfConfirmed,
			Layer:      "L1",
			Weakness:   "BTV-L1-002",
			Description: fmt.Sprintf(
				"%d of the node's %d connected peers (%.0f%%) dial from a single IP (%s); "+
					"the node's entire view of the network is attacker-controlled. "+
					"This is the confirmed post-exploitation state of an eclipse attack "+
					"(BTV-L1-002): the attacker can now censor transactions (the victim "+
					"never sees them), cleanse information (feed it a private chain view), "+
					"and replace the victim's view of consensus for 0-conf confirmations, "+
					"balance reads, and any off-chain logic that trusts this node.",
				stats.MaxPerIP, stats.Total, stats.Fraction*100, stats.MaxIP),
			Evidence: evidence,
			PoC:      "playbooks/evm/p2p-eclipse.yaml",
			Target:   ep.Name,
			Source:   "p2p-eclipse",
		}}

	case stats.Fraction >= 0.5:
		return []core.Finding{{
			ID:         "p2peclipse-partial",
			Title:      fmt.Sprintf("Partial eclipse: %d/%d peer slots held by one IP", stats.MaxPerIP, stats.Total),
			Severity:   core.SevMedium,
			Confidence: core.ConfConfirmed,
			Layer:      "L1",
			Weakness:   "BTV-L1-002",
			Description: fmt.Sprintf(
				"A single IP (%s) holds %d of %d peer slots (%.0f%%). The attacker "+
					"controls a majority of the node's network view but not all of it; "+
					"honest peers can still leak through, so censorship and view "+
					"replacement are degraded, not total.",
				stats.MaxIP, stats.MaxPerIP, stats.Total, stats.Fraction*100),
			Evidence: evidence,
			PoC:      "playbooks/evm/p2p-eclipse.yaml",
			Target:   ep.Name,
			Source:   "p2p-eclipse",
		}}

	default:
		return []core.Finding{{
			ID:       "p2peclipse-negative",
			Title:    "Eclipse not sustained: peer set is network-diverse",
			Severity: core.SevInfo,
			Layer:    "L1",
			Description: fmt.Sprintf(
				"No single IP holds a majority of the node's %d peer slots "+
					"(max %.0f%% from %s); the executed attack did not isolate the node.",
				stats.Total, stats.Fraction*100, stats.MaxIP),
			Evidence: evidence,
			Target:   ep.Name,
			Source:   "p2p-eclipse",
		}}
	}
}

// fetchPeers calls admin_peers on one endpoint. The helper mirrors
// nodeaudit's JSON-RPC pattern but is duplicated here so the packages
// stay decoupled.
func fetchPeers(ctx context.Context, url string) ([]adminPeer, error) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "admin_peers", "params": []any{},
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := rpcClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d: %.200s", resp.StatusCode, data)
	}
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", out.Error.Code, out.Error.Message)
	}
	return parseAdminPeers(out.Result)
}

// rpcEndpoints returns the target's RPC endpoints (role rpc or unset).
func rpcEndpoints(tgt *core.Target) []core.Endpoint {
	var out []core.Endpoint
	for _, ep := range tgt.Endpoints {
		if ep.Role == "" || ep.Role == "rpc" {
			out = append(out, ep)
		}
	}
	return out
}
