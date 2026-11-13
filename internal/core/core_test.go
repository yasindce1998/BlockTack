package core

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func loadTaxonomy(t *testing.T) *Taxonomy {
	t.Helper()
	path := filepath.Join("..", "..", "taxonomy", "blocktack-matrix.yaml")
	tx, err := LoadTaxonomy(path)
	if err != nil {
		t.Fatalf("load taxonomy: %v", err)
	}
	return tx
}

func TestTaxonomyIDsUniqueAndWellFormed(t *testing.T) {
	tx := loadTaxonomy(t)
	seen := map[string]bool{}
	for _, l := range tx.Layers {
		for _, w := range l.Weaknesses {
			if seen[w.ID] {
				t.Errorf("duplicate weakness ID %s", w.ID)
			}
			seen[w.ID] = true
			wantPrefix := "BTV-" + l.ID + "-"
			if len(w.ID) < len(wantPrefix) || w.ID[:len(wantPrefix)] != wantPrefix {
				t.Errorf("weakness %s does not match layer %s prefix %s", w.ID, l.ID, wantPrefix)
			}
			if w.Name == "" {
				t.Errorf("weakness %s has no name", w.ID)
			}
		}
	}
	if len(seen) < 40 {
		t.Errorf("expected at least 40 weaknesses, got %d", len(seen))
	}
}

func TestTaxonomyLookup(t *testing.T) {
	tx := loadTaxonomy(t)
	if _, ok := tx.Weakness("BTV-L2-003"); !ok {
		t.Error("expected BTV-L2-003 (oracle manipulation) in taxonomy")
	}
	if _, ok := tx.Weakness("BTV-L9-999"); ok {
		t.Error("lookup of bogus ID should fail")
	}
}

func TestSARIFRoundTrip(t *testing.T) {
	findings := []Finding{
		{
			ID: "test-1", Title: "Exposed txpool", Severity: SevMedium,
			Layer: "L0", Weakness: "BTV-L0-001", Source: "recon",
			Evidence: `{"pending":0}`,
		},
		{
			ID: "test-2", Title: "Broken access control", Severity: SevCritical,
			Layer: "L2", Weakness: "BTV-L2-002", Source: "slither",
		},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings); err != nil {
		t.Fatalf("write sarif: %v", err)
	}
	parsed, err := ParseSARIFResults(buf.Bytes(), "test")
	if err != nil {
		t.Fatalf("parse sarif: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(parsed))
	}
	for i, want := range findings {
		got := parsed[i]
		if got.Weakness != want.Weakness {
			t.Errorf("finding %d: weakness = %q, want %q", i, got.Weakness, want.Weakness)
		}
		if got.Severity != want.Severity {
			t.Errorf("finding %d: severity = %q, want %q", i, got.Severity, want.Severity)
		}
	}
}

func TestTargetAuthorizationGuardrails(t *testing.T) {
	noAuth := &Target{Name: "t", Authorization: Authorization{Declared: false}}
	if err := noAuth.ValidateSafeMode(true); err == nil {
		t.Error("target without authorization must be refused")
	}

	expired := &Target{Name: "t", Authorization: Authorization{
		Declared: true, Expires: mustTime("2020-01-01T00:00:00Z"),
	}}
	if err := expired.ValidateSafeMode(true); err == nil {
		t.Error("expired authorization must be refused")
	}

	live := &Target{Name: "t", Authorization: Authorization{
		Declared: true, Expires: mustTime("2099-01-01T00:00:00Z"),
	}, Endpoints: []Endpoint{{Name: "rpc", URL: "http://example.com:8545"}}}
	if err := live.ValidateSafeMode(true); err == nil {
		t.Error("safe mode must refuse non-local, non-authorized endpoints")
	}
	if err := live.ValidateSafeMode(false); err != nil {
		t.Errorf("unsafe mode should only require authorization: %v", err)
	}

	local := &Target{Name: "t", Authorization: Authorization{
		Declared: true, Expires: mustTime("2099-01-01T00:00:00Z"),
	}, Endpoints: []Endpoint{{Name: "rpc", URL: "http://127.0.0.1:8545"}}}
	if err := local.ValidateSafeMode(true); err != nil {
		t.Errorf("local endpoint should pass safe mode: %v", err)
	}
}

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestLoadTargetExample(t *testing.T) {
	path := filepath.Join("..", "..", "examples", "targets", "local-anvil.yaml")
	tgt, err := LoadTarget(path)
	if err != nil {
		t.Fatalf("load example target: %v", err)
	}
	if tgt.Name != "local-anvil" {
		t.Errorf("name = %q, want local-anvil", tgt.Name)
	}
	if !tgt.Authorization.Declared {
		t.Error("example target should declare authorization")
	}
	if err := tgt.ValidateSafeMode(true); err != nil {
		t.Errorf("example target should pass safe mode: %v", err)
	}
}

func TestSaveAndLoadFindingsJSON(t *testing.T) {
	f := Finding{ID: "x", Title: "x", Severity: SevHigh}
	path := filepath.Join(t.TempDir(), "findings.json")
	if err := SaveFindingsJSON([]Finding{f}, path); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file missing: %v", err)
	}
	loaded, err := LoadFindingsJSON(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded) != 1 || loaded[0].ID != "x" {
		t.Fatalf("unexpected round trip: %+v", loaded)
	}
	if loaded[0].Confidence != ConfMedium {
		t.Errorf("Normalize should fill confidence, got %q", loaded[0].Confidence)
	}
}
