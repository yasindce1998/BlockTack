package p2pattack

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/blocktack/blocktack/internal/core"
)

// cannedEclipsed is an admin_peers response in which every peer slot is
// held by the same IP (127.0.0.1), as produced by the p2p-eclipse
// campaign's attacker swarm dialing the victim.
const cannedEclipsed = `[
  {"enode":"enode://a@127.0.0.1:52640","name":"Geth/v1.17.10","network":{"remoteAddress":"127.0.0.1:52640","localAddress":"127.0.0.1:30304","inbound":true}},
  {"enode":"enode://b@127.0.0.1:52641","name":"Geth/v1.17.10","network":{"remoteAddress":"127.0.0.1:52641","localAddress":"127.0.0.1:30304","inbound":true}},
  {"enode":"enode://c@127.0.0.1:52642","name":"Geth/v1.17.10","network":{"remoteAddress":"127.0.0.1:52642","localAddress":"127.0.0.1:30304","inbound":true}},
  {"enode":"enode://d@127.0.0.1:52643","name":"Geth/v1.17.10","network":{"remoteAddress":"127.0.0.1:52643","localAddress":"127.0.0.1:30304","inbound":true}},
  {"enode":"enode://e@127.0.0.1:52644","name":"Geth/v1.17.10","network":{"remoteAddress":"127.0.0.1:52644","localAddress":"127.0.0.1:30304","inbound":true}},
  {"enode":"enode://f@127.0.0.1:52645","name":"Geth/v1.17.10","network":{"remoteAddress":"127.0.0.1:52645","localAddress":"127.0.0.1:30304","inbound":true}},
  {"enode":"enode://g@127.0.0.1:52646","name":"Geth/v1.17.10","network":{"remoteAddress":"127.0.0.1:52646","localAddress":"127.0.0.1:30304","inbound":true}},
  {"enode":"enode://h@127.0.0.1:52647","name":"Geth/v1.17.10","network":{"remoteAddress":"127.0.0.1:52647","localAddress":"127.0.0.1:30304","inbound":true}}
]`

const cannedDiverse = `[
  {"enode":"enode://a@10.0.0.1:30303","name":"Geth/v1.17.10","network":{"remoteAddress":"10.0.0.1:51234"}},
  {"enode":"enode://b@10.0.0.1:30303","name":"Geth/v1.17.10","network":{"remoteAddress":"10.0.0.1:51235"}},
  {"enode":"enode://c@192.168.1.9:30303","name":"Nethermind/v1.25.3","network":{"remoteAddress":"192.168.1.9:51236"}},
  {"enode":"enode://d@172.16.0.4:30303","name":"besu/v24","network":{"remoteAddress":"172.16.0.4:51237"}},
  {"enode":"enode://e@172.16.0.4:30303","name":"besu/v24","network":{"remoteAddress":"172.16.0.4:51238"}}
]`

const cannedPartial = `[
  {"enode":"enode://a@127.0.0.1:50001","name":"Geth/v1.17.10","network":{"remoteAddress":"127.0.0.1:50001"}},
  {"enode":"enode://b@127.0.0.1:50002","name":"Geth/v1.17.10","network":{"remoteAddress":"127.0.0.1:50002"}},
  {"enode":"enode://c@127.0.0.1:50003","name":"Geth/v1.17.10","network":{"remoteAddress":"127.0.0.1:50003"}},
  {"enode":"enode://d@10.1.2.3:50004","name":"Geth/v1.17.10","network":{"remoteAddress":"10.1.2.3:50004"}}
]`

func mustParse(t *testing.T, raw string) []adminPeer {
	t.Helper()
	peers, err := parseAdminPeers([]byte(raw))
	if err != nil {
		t.Fatalf("parse admin_peers: %v", err)
	}
	return peers
}

func TestParseAdminPeers(t *testing.T) {
	peers := mustParse(t, cannedEclipsed)
	if len(peers) != 8 {
		t.Fatalf("peers = %d, want 8", len(peers))
	}
	if peers[0].Network.RemoteAddress != "127.0.0.1:52640" {
		t.Errorf("remoteAddress = %q, want 127.0.0.1:52640", peers[0].Network.RemoteAddress)
	}
	if !peers[0].Network.Inbound {
		t.Error("inbound should parse as true")
	}
	if peers[3].Enode != "enode://d@127.0.0.1:52643" {
		t.Errorf("enode = %q", peers[3].Enode)
	}
}

func TestParseAdminPeersRejectsGarbage(t *testing.T) {
	if _, err := parseAdminPeers([]byte(`{"not":"a list"}`)); err == nil {
		t.Error("object payload should not parse as a peer list")
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"10.0.0.7:52642":  "10.0.0.7",
		"[::1]:52642":     "::1",
		"192.168.1.1":     "192.168.1.1", // no port: returned as-is
		"example.com:443": "example.com",
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAnalyzePeersEclipsed(t *testing.T) {
	s := analyzePeers(mustParse(t, cannedEclipsed))
	if s.Total != 8 {
		t.Errorf("total = %d, want 8", s.Total)
	}
	if s.DistinctIPs != 1 {
		t.Errorf("distinct ips = %d, want 1", s.DistinctIPs)
	}
	if s.MaxPerIP != 8 || s.MaxIP != "127.0.0.1" {
		t.Errorf("max per ip = %d@%s, want 8@127.0.0.1", s.MaxPerIP, s.MaxIP)
	}
	if s.Fraction != 1.0 {
		t.Errorf("fraction = %v, want 1.0", s.Fraction)
	}
}

func TestAnalyzePeersDiverse(t *testing.T) {
	s := analyzePeers(mustParse(t, cannedDiverse))
	if s.Total != 5 || s.DistinctIPs != 3 {
		t.Fatalf("total/distinct = %d/%d, want 5/3", s.Total, s.DistinctIPs)
	}
	if s.MaxPerIP != 2 {
		t.Errorf("max per ip = %d, want 2", s.MaxPerIP)
	}
	if want := 2.0 / 5.0; s.Fraction != want {
		t.Errorf("fraction = %v, want %v", s.Fraction, want)
	}
}

func TestAnalyzePeersEmpty(t *testing.T) {
	s := analyzePeers(nil)
	if s.Total != 0 || s.Fraction != 0 || s.MaxIP != "" {
		t.Errorf("empty peer set graded %+v, want zero stats", s)
	}
}

func TestGradeCriticalWhenAllSlotsOneIP(t *testing.T) {
	fs := gradeEndpoint(core.Endpoint{Name: "victim-rpc", URL: "http://127.0.0.1:8546", Role: "rpc"},
		analyzePeers(mustParse(t, cannedEclipsed)))
	if len(fs) != 1 {
		t.Fatalf("findings = %d, want 1", len(fs))
	}
	f := fs[0]
	if f.ID != "p2peclipse-executed" {
		t.Fatalf("id = %s, want p2peclipse-executed", f.ID)
	}
	if f.Severity != core.SevCritical {
		t.Errorf("severity = %s, want critical", f.Severity)
	}
	if f.Confidence != core.ConfConfirmed {
		t.Errorf("confidence = %s, want confirmed", f.Confidence)
	}
	if f.Weakness != "BTV-L1-002" || f.Layer != "L1" {
		t.Errorf("weakness/layer = %s/%s, want BTV-L1-002/L1", f.Weakness, f.Layer)
	}
	if f.Source != "p2p-eclipse" {
		t.Errorf("source = %s, want p2p-eclipse", f.Source)
	}
	for _, want := range []string{"peers=8", "distinct_ips=1", "fraction=1.00"} {
		if !strings.Contains(f.Evidence, want) {
			t.Errorf("evidence %q missing %q", f.Evidence, want)
		}
	}
}

func TestGradePartialEclipse(t *testing.T) {
	// 3/4 peers from one IP: majority but below the 0.9 full-eclipse bar.
	fs := gradeEndpoint(core.Endpoint{Name: "victim-rpc", Role: "rpc"},
		analyzePeers(mustParse(t, cannedPartial)))
	if len(fs) != 1 || fs[0].ID != "p2peclipse-partial" {
		t.Fatalf("expected a single p2peclipse-partial finding, got %+v", fs)
	}
	if fs[0].Severity != core.SevMedium {
		t.Errorf("severity = %s, want medium", fs[0].Severity)
	}
}

func TestGradeDiverseTopologyIsInformational(t *testing.T) {
	fs := gradeEndpoint(core.Endpoint{Name: "victim-rpc", Role: "rpc"},
		analyzePeers(mustParse(t, cannedDiverse)))
	if len(fs) != 1 || fs[0].ID != "p2peclipse-negative" {
		t.Fatalf("expected a single p2peclipse-negative finding, got %+v", fs)
	}
	if fs[0].Severity != core.SevInfo {
		t.Errorf("severity = %s, want info", fs[0].Severity)
	}
}

func TestGradeNoPeers(t *testing.T) {
	fs := gradeEndpoint(core.Endpoint{Name: "victim-rpc", Role: "rpc"}, peerStats{})
	if len(fs) != 1 || fs[0].ID != "p2peclipse-no-peers" {
		t.Fatalf("expected a single p2peclipse-no-peers finding, got %+v", fs)
	}
}

func TestGradeSinglePeerIsNotFullEclipse(t *testing.T) {
	// One peer from one IP is trivially 100%, but a single-slot
	// isolation should not be graded a confirmed full eclipse.
	s := analyzePeers(mustParse(t,
		`[{"enode":"enode://a@127.0.0.1:50001","network":{"remoteAddress":"127.0.0.1:50001"}}]`))
	fs := gradeEndpoint(core.Endpoint{Name: "victim-rpc", Role: "rpc"}, s)
	if len(fs) != 1 || fs[0].ID != "p2peclipse-partial" {
		t.Fatalf("single-peer set should grade partial, got %+v", fs)
	}
}

func TestRPCEndpointsFiltersToRPCRole(t *testing.T) {
	tgt := &core.Target{
		Endpoints: []core.Endpoint{
			{Name: "rpc", Role: "rpc", URL: "http://127.0.0.1:8546"},
			{Name: "api", Role: "api", URL: "http://127.0.0.1:8080"},
			{Name: "unroled", URL: "http://127.0.0.1:8547"},
		},
	}
	eps := rpcEndpoints(tgt)
	if len(eps) != 2 {
		t.Fatalf("endpoints = %d, want 2 (rpc + unroled)", len(eps))
	}
}

// TestJSONFieldNames pins the JSON tags of the wire struct so a silent
// rename cannot break parsing of real admin_peers payloads.
func TestJSONFieldNames(t *testing.T) {
	raw := `{"enode":"e","name":"n","network":{"remoteAddress":"1.2.3.4:1","localAddress":"5.6.7.8:2","inbound":true}}`
	var p adminPeer
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	if p.Network.RemoteAddress != "1.2.3.4:1" || p.Network.LocalAddress != "5.6.7.8:2" || !p.Network.Inbound {
		t.Errorf("unexpected decode: %+v", p)
	}
}
