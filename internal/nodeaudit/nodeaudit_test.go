package nodeaudit

import (
	"encoding/json"
	"testing"
)

func TestExtractVersion(t *testing.T) {
	cases := []struct {
		in   string
		want []int
	}{
		{"Geth/v1.10.7-stable-187ad8dc-20240228/linux-amd64/go1.21.7", []int{1, 10, 7}},
		{"Geth/v1.13.4-stable/linux-amd64/go1.21", []int{1, 13, 4}},
		{"anvil/v1.9.0 (6056c5845d)", []int{1, 9, 0}},
		{"Nethermind/v1.25.3+9b4a29c7/linux-x64/dotnet8.0", []int{1, 25, 3}},
		{"no version here", nil},
	}
	for _, c := range cases {
		got := extractVersion(c.in)
		if len(got) != len(c.want) {
			t.Errorf("extractVersion(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("extractVersion(%q) = %v, want %v", c.in, got, c.want)
				break
			}
		}
	}
}

func TestVersionLess(t *testing.T) {
	if !versionLess([]int{1, 10, 7}, []int{1, 10, 8}) {
		t.Error("1.10.7 should be < 1.10.8")
	}
	if versionLess([]int{1, 10, 8}, []int{1, 10, 8}) {
		t.Error("1.10.8 should not be < 1.10.8")
	}
	if versionLess([]int{1, 11, 0}, []int{1, 10, 8}) {
		t.Error("1.11.0 should not be < 1.10.8")
	}
	if !versionLess([]int{1, 10}, []int{1, 10, 1}) {
		t.Error("1.10 should be < 1.10.1 (missing components count as 0)")
	}
}

func TestCVEDBLoadsAndMatchesGeth(t *testing.T) {
	db, err := loadCVEDB()
	if err != nil {
		t.Fatalf("load cve db: %v", err)
	}
	var geth *clientEntry
	for i := range db.Clients {
		if db.Clients[i].Name == "geth" {
			geth = &db.Clients[i]
		}
	}
	if geth == nil {
		t.Fatal("geth entry missing from cve db")
	}
	if len(geth.Vulnerabilities) == 0 {
		t.Fatal("geth entry has no vulnerabilities")
	}
	// A pre-fix version must compare as vulnerable.
	parsed := extractVersion("Geth/v1.10.7-stable/linux-amd64/go1.21")
	for _, v := range geth.Vulnerabilities {
		if !versionLess(parsed, parseFixedIn(v.FixedIn)) {
			t.Errorf("Geth/v1.10.7 should be vulnerable to %s (fixed in %s)", v.ID, v.FixedIn)
		}
	}
	// A post-fix version must not.
	parsed = extractVersion("Geth/v1.13.4-stable/linux-amd64/go1.21")
	for _, v := range geth.Vulnerabilities {
		if versionLess(parsed, parseFixedIn(v.FixedIn)) {
			t.Errorf("Geth/v1.13.4 should not be vulnerable to %s", v.ID)
		}
	}
}

func TestClassifyFuzzResponse(t *testing.T) {
	if classifyFuzzResponse(200, `{"error":{"code":-32601}}`, nil) != fuzzOK {
		t.Error("proper JSON-RPC error should be fuzzOK")
	}
	if classifyFuzzResponse(500, "boom", nil) != fuzzSuspicious {
		t.Error("HTTP 500 should be suspicious")
	}
	if classifyFuzzResponse(200, "", nil) != fuzzSuspicious {
		t.Error("empty body should be suspicious")
	}
	if classifyFuzzResponse(0, "", errDummy{}) != fuzzDown {
		t.Error("transport error should be down")
	}
}

type errDummy struct{}

func (errDummy) Error() string { return "transport failure" }

func TestMempoolParsing(t *testing.T) {
	raw := `{
	  "pending": {
	    "0xabc": {
	      "0": {"to": "0xdef", "hash": "0x111"},
	      "1": {"to": "0xdef", "hash": "0x112"}
	    }
	  },
	  "queued": {}
	}`
	var content txpoolContent
	if err := json.Unmarshal([]byte(raw), &content); err != nil {
		t.Fatalf("parse txpool content: %v", err)
	}
	pending := 0
	for _, byNonce := range content.Pending {
		pending += len(byNonce)
	}
	if pending != 2 {
		t.Errorf("pending = %d, want 2", pending)
	}
}

func TestPeerParsingAndSubnets(t *testing.T) {
	raw := `[
	  {"enode":"enode://a@10.0.0.1:30303","name":"Geth/v1.13.4","network":{"remoteAddress":"10.0.0.1:30303"}},
	  {"enode":"enode://b@10.0.0.2:30303","name":"Geth/v1.13.4","network":{"remoteAddress":"10.0.0.2:30303"}},
	  {"enode":"enode://c@10.0.0.3:30303","name":"Nethermind/v1.25.3","network":{"remoteAddress":"10.0.0.3:30303"}},
	  {"enode":"enode://d@192.168.1.9:30303","name":"besu/v24","network":{"remoteAddress":"192.168.1.9:30303"}}
	]`
	var peers []adminPeer
	if err := json.Unmarshal([]byte(raw), &peers); err != nil {
		t.Fatalf("parse peers: %v", err)
	}
	if len(peers) != 4 {
		t.Fatalf("peers = %d, want 4", len(peers))
	}
	subnets := map[string]int{}
	for _, p := range peers {
		parts := splitDots(p.Network.RemoteAddress[:len(p.Network.RemoteAddress)-7])
		if len(parts) == 4 {
			subnets[parts[0]+"."+parts[1]+"."+parts[2]]++
		}
	}
	if subnets["10.0.0"] != 3 {
		t.Errorf("subnet 10.0.0 count = %d, want 3", subnets["10.0.0"])
	}
}
