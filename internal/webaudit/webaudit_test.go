package webaudit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blocktack/blocktack/internal/core"
)

func TestAuditFindsExposures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			// No security headers, directory listing body.
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body><h1>Directory listing for /</h1></body></html>"))
		case "/.env":
			_, _ = w.Write([]byte("API_KEY=fixture-secret\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	tgt := &core.Target{
		Name: "fixture",
		Endpoints: []core.Endpoint{
			{Name: "api", Role: "api", URL: srv.URL},
		},
	}
	findings, err := Run(context.Background(), tgt)
	if err != nil {
		t.Fatalf("run webaudit: %v", err)
	}

	got := map[string]bool{}
	for _, f := range findings {
		got[f.ID] = true
	}
	for _, want := range []string{"webaudit-plaintext", "webaudit-dirlist", "webaudit-exposed-path", "webaudit-header-noop", "webaudit-header-framing"} {
		if !got[want] {
			t.Errorf("expected finding %s, got %v", want, ids(findings))
		}
	}
	// The exposed path must be the .env with high severity.
	for _, f := range findings {
		if f.ID == "webaudit-exposed-path" {
			if f.Severity != core.SevHigh || f.Title != "Committed .env file served by the web root" {
				t.Errorf("unexpected exposed-path finding: %+v", f)
			}
		}
	}
}

func TestAuditCleanServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		http.NotFound(w, r)
	}))
	defer srv.Close()

	tgt := &core.Target{
		Name: "clean",
		Endpoints: []core.Endpoint{
			{Name: "api", Role: "api", URL: srv.URL},
		},
	}
	findings, err := Run(context.Background(), tgt)
	if err != nil {
		t.Fatalf("run webaudit: %v", err)
	}
	// The httptest server is plain HTTP by construction, so the
	// low-severity plaintext finding is expected; nothing else should fire.
	if len(findings) != 1 || findings[0].ID != "webaudit-plaintext" {
		t.Errorf("expected only the plaintext finding on hardened server, got %v", ids(findings))
	}
}

func TestNoEndpointsInfo(t *testing.T) {
	findings, err := Run(context.Background(), &core.Target{Name: "t"})
	if err != nil {
		t.Fatalf("run webaudit: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "webaudit-no-endpoints" {
		t.Errorf("expected no-endpoints info finding, got %v", ids(findings))
	}
}

func ids(fs []core.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.ID
	}
	return out
}
