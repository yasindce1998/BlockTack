package nodeaudit

import (
	"context"
	"fmt"
	"strings"

	"github.com/blocktack/blocktack/internal/core"
)

// fuzzPayload is one malformed-input probe for the RPC fuzz battery.
type fuzzPayload struct {
	name   string
	body   string
	expect string // what a robust implementation should do
}

// fuzzBattery returns the malformed-input probes. All of them target
// read-only or nonexistent methods; none mutates chain state.
func fuzzBattery() []fuzzPayload {
	bigArray := make([]string, 0, 5000)
	for i := 0; i < 5000; i++ {
		bigArray = append(bigArray, fmt.Sprintf("%d", i))
	}
	return []fuzzPayload{
		{name: "invalid-json", body: `{not json at all`, expect: "HTTP 4xx/5xx or JSON-RPC parse error"},
		{name: "null-method", body: `{"jsonrpc":"2.0","id":1,"method":null}`, expect: "method-not-found error"},
		{name: "wrong-param-type", body: `{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[{"x":[1,2,{"y":null}]}]}`, expect: "invalid-params error"},
		{name: "bool-id", body: `{"jsonrpc":"2.0","id":true,"method":"eth_chainId","params":[]}`, expect: "parse error or tolerated"},
		{name: "unknown-method-huge-params", body: fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"eth_nonexistentMethod","params":[%s]`, `"`+strings.Repeat("A", 4096)+`"]`), expect: "method-not-found error"},
		{name: "oversized-array", body: fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[%s]`, `"`+strings.Join(bigArray, `","`)+`"]`), expect: "invalid-params error, no crash"},
		{name: "negative-block-tag", body: `{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["0x0000000000000000000000000000000000000000","-0x1"]}`, expect: "invalid-params error"},
	}
}

// classifyFuzzResponse rates one fuzz response: ok (proper error),
// suspicious (HTTP 5xx or empty), or down (transport failure).
type fuzzVerdict int

const (
	fuzzOK fuzzVerdict = iota
	fuzzSuspicious
	fuzzDown
)

func classifyFuzzResponse(status int, body string, err error) fuzzVerdict {
	if err != nil {
		return fuzzDown
	}
	if status >= 500 || strings.TrimSpace(body) == "" {
		return fuzzSuspicious
	}
	return fuzzOK
}

// rpcFuzz sends a battery of malformed JSON-RPC payloads and verifies
// the node stays healthy afterwards (a DoS signal).
func rpcFuzz(ctx context.Context, tgt *core.Target) ([]core.Finding, error) {
	var findings []core.Finding
	for _, ep := range rpcEndpoints(tgt) {
		// Baseline health check.
		if _, err := rpcCall(ctx, ep.URL, "eth_chainId", []any{}); err != nil {
			findings = append(findings, core.Finding{
				ID:          "nodeaudit-fuzz-unreachable",
				Title:       "RPC endpoint unreachable before fuzzing",
				Severity:    core.SevInfo,
				Layer:       "L0",
				Description: err.Error(),
				Target:      ep.Name,
			})
			continue
		}

		suspicious, down := 0, 0
		for _, p := range fuzzBattery() {
			status, body, err := rawRPC(ctx, ep.URL, []byte(p.body))
			switch classifyFuzzResponse(status, body, err) {
			case fuzzSuspicious:
				suspicious++
				findings = append(findings, core.Finding{
					ID:       "nodeaudit-fuzz-suspicious",
					Title:    fmt.Sprintf("Suspicious response to malformed RPC input: %s", p.name),
					Severity: core.SevLow,
					Layer:    "L0",
					Weakness: "BTV-L0-008",
					Description: fmt.Sprintf(
						"The node answered probe %q with HTTP %d (expected %s). "+
							"Malformed-input handling may be fragile.", p.name, status, p.expect),
					Evidence: truncate(body, 200),
					Target:   ep.Name,
				})
			case fuzzDown:
				down++
			}
		}

		// Post-fuzz health check: an unresponsive node is a DoS finding.
		if _, err := rpcCall(ctx, ep.URL, "eth_chainId", []any{}); err != nil {
			findings = append(findings, core.Finding{
				ID:         "nodeaudit-fuzz-dos",
				Title:      "Node unresponsive after malformed RPC input",
				Severity:   core.SevCritical,
				Confidence: core.ConfConfirmed,
				Layer:      "L0",
				Weakness:   "BTV-L0-008",
				Description: fmt.Sprintf(
					"After %d malformed-input probes (%d transport failures, %d suspicious "+
						"responses), the node no longer answers eth_chainId — remote denial "+
						"of service by malformed input.", len(fuzzBattery()), down, suspicious),
				Evidence: fmt.Sprintf("unreachable: %v", err),
				Target:   ep.Name,
			})
			continue
		}

		if suspicious == 0 && down == 0 {
			findings = append(findings, core.Finding{
				ID:       "nodeaudit-fuzz-clean",
				Title:    "Node survives malformed RPC battery",
				Severity: core.SevInfo,
				Layer:    "L0",
				Description: fmt.Sprintf(
					"All %d malformed-input probes were rejected with proper errors and the "+
						"node remained responsive.", len(fuzzBattery())),
				Target: ep.Name,
			})
		}
	}
	return normalize(findings, "rpc-fuzz"), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
