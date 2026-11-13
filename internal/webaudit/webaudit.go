// Package webaudit checks off-chain endpoints (role api, indexer,
// frontend) for exposure: plaintext HTTP, missing security headers,
// directory listings, and committed secrets in the web root.
package webaudit

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/blocktack/blocktack/internal/core"
)

var webClient = &http.Client{
	Timeout: 10 * time.Second,
	// Do not follow redirects: a redirect away from /.env is itself the
	// control working.
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// sensitivePath is a path that should never be served by a web root.
type sensitivePath struct {
	path     string
	title    string
	severity core.Severity
	confirm  func(body string) bool
}

var sensitivePaths = []sensitivePath{
	{
		path:     "/.env",
		title:    "Committed .env file served by the web root",
		severity: core.SevHigh,
		confirm:  func(b string) bool { return strings.Contains(b, "=") },
	},
	{
		path:     "/.git/config",
		title:    "Exposed .git repository",
		severity: core.SevHigh,
		confirm:  func(b string) bool { return strings.Contains(b, "[core]") || strings.Contains(b, "[remote") },
	},
	{
		path:     "/debug/pprof/",
		title:    "Exposed Go pprof debug endpoint",
		severity: core.SevHigh,
		confirm:  func(b string) bool { return strings.Contains(b, "goroutine") || strings.Contains(b, "profiles") },
	},
	{
		path:     "/graphql",
		title:    "Exposed GraphQL endpoint",
		severity: core.SevMedium,
		confirm:  func(b string) bool { return strings.Contains(b, "data") || strings.Contains(b, "errors") },
	},
}

// Run audits every api/indexer/frontend endpoint of the target.
// All requests are GETs; nothing is submitted or mutated.
func Run(ctx context.Context, tgt *core.Target) ([]core.Finding, error) {
	var findings []core.Finding
	audited := 0
	for _, ep := range tgt.Endpoints {
		switch ep.Role {
		case "api", "indexer", "frontend":
		default:
			continue
		}
		audited++
		findings = append(findings, auditEndpoint(ctx, ep)...)
	}
	if audited == 0 {
		findings = append(findings, core.Finding{
			ID:       "webaudit-no-endpoints",
			Title:    "No off-chain endpoints in target",
			Severity: core.SevInfo,
			Layer:    "L4",
			Description: "The target defines no endpoints with role api, indexer or frontend; " +
				"nothing to audit.",
		})
	}
	for i := range findings {
		findings[i].Normalize()
		if findings[i].Source == "" {
			findings[i].Source = "web-audit"
		}
	}
	return findings, nil
}

func auditEndpoint(ctx context.Context, ep core.Endpoint) []core.Finding {
	var findings []core.Finding
	base := strings.TrimSuffix(ep.URL, "/")
	target := ep.Name + " (" + ep.URL + ")"

	u, err := url.Parse(ep.URL)
	if err == nil && u.Scheme == "http" {
		findings = append(findings, core.Finding{
			ID:       "webaudit-plaintext",
			Title:    "Off-chain endpoint served over plaintext HTTP",
			Severity: core.SevLow,
			Layer:    "L4",
			Weakness: "BTV-L4-003",
			Description: "The endpoint is reachable over unencrypted HTTP. Session tokens, API " +
				"keys and responses are interceptable on the network path.",
			Target: target,
		})
	}

	// Root document: security headers and directory listing.
	status, headers, body := fetch(ctx, base+"/")
	if status > 0 {
		if findings2 := headerFindings(headers, target); len(findings2) > 0 {
			findings = append(findings, findings2...)
		}
		if isDirectoryListing(body) {
			findings = append(findings, core.Finding{
				ID:       "webaudit-dirlist",
				Title:    "Directory listing enabled",
				Severity: core.SevMedium,
				Layer:    "L4",
				Weakness: "BTV-L4-003",
				Description: "The web root serves a directory index, disclosing the full file " +
					"tree (and any files that should not be deployed).",
				Target:   target,
				Evidence: firstLine(body, 200),
			})
		}

		for _, sp := range sensitivePaths {
			s2, _, b2 := fetch(ctx, base+sp.path)
			if s2 == http.StatusOK && sp.confirm(b2) {
				findings = append(findings, core.Finding{
					ID:         "webaudit-exposed-path",
					Title:      sp.title,
					Severity:   sp.severity,
					Confidence: core.ConfConfirmed,
					Layer:      "L4",
					Weakness:   "BTV-L4-003",
					Description: fmt.Sprintf(
						"GET %s returned 200 with expected content — the resource is exposed to "+
							"unauthenticated callers.", sp.path),
					Target:   target,
					Evidence: firstLine(b2, 200),
					PoC:      fmt.Sprintf("curl %s%s", base, sp.path),
				})
			}
		}
	}
	return findings
}

func headerFindings(headers http.Header, target string) []core.Finding {
	var findings []core.Finding
	if headers.Get("X-Content-Type-Options") == "" {
		findings = append(findings, core.Finding{
			ID:       "webaudit-header-noop",
			Title:    "Missing X-Content-Type-Options header",
			Severity: core.SevLow,
			Layer:    "L4",
			Weakness: "BTV-L4-002",
			Description: "Without nosniff, browsers may sniff content types, enabling MIME-" +
				"confusion attacks against users of the frontend.",
			Target: target,
		})
	}
	if headers.Get("X-Frame-Options") == "" && headers.Get("Content-Security-Policy") == "" {
		findings = append(findings, core.Finding{
			ID:       "webaudit-header-framing",
			Title:    "No clickjacking protections (X-Frame-Options/CSP)",
			Severity: core.SevLow,
			Layer:    "L4",
			Weakness: "BTV-L4-002",
			Description: "The endpoint can be framed by attacker pages — relevant for wallet " +
				"and approval UIs where misclicks cost money.",
			Target: target,
		})
	}
	return findings
}

// fetch performs a GET and returns status, headers and body.
func fetch(ctx context.Context, url string) (int, http.Header, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, ""
	}
	resp, err := webClient.Do(req)
	if err != nil {
		return 0, nil, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return resp.StatusCode, resp.Header, string(body)
}

func isDirectoryListing(body string) bool {
	return strings.Contains(body, "Index of /") || strings.Contains(body, "Directory listing for")
}

func firstLine(s string, n int) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > n {
		s = s[:n] + "..."
	}
	return s
}
