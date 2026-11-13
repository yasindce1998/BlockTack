package report

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blocktack/blocktack/internal/core"
	"github.com/blocktack/blocktack/internal/correlate"
)

// testTaxonomy loads the real taxonomy from the repo.
func testTaxonomy(t *testing.T) *core.Taxonomy {
	t.Helper()
	tx, err := core.LoadTaxonomy(filepath.Join("..", "..", "taxonomy", "blocktack-matrix.yaml"))
	if err != nil {
		t.Fatalf("load taxonomy: %v", err)
	}
	return tx
}

// fixtureTarget mirrors the authorization shape of corpus targets.
func fixtureTarget() *core.Target {
	return &core.Target{
		Name:  "naive-oracle-vault-lab",
		Chain: core.ChainRef{Type: "evm", Network: "local", ChainID: 31337},
		Contracts: []core.Contract{{
			Name:    "NaiveOracleVault",
			Address: "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
		}},
		Endpoints: []core.Endpoint{{
			Name: "local-anvil",
			Role: "rpc",
			URL:  "http://127.0.0.1:8545",
		}},
		Authorization: core.Authorization{
			Declared:     true,
			AuthorizedBy: "Dr. Elena Voss, CISO — Vault Labs Inc.",
			Scope:        "naive-oracle-vault fixture on a local anvil instance; transactions broadcast to the local chain only",
			Expires:      time.Date(2027, 12, 31, 0, 0, 0, 0, time.UTC),
		},
	}
}

// fixtureFindings mirrors the naive-oracle-vault campaign output shape:
// fingerprint, oracle dependency (BTV-L2-003), simulate-call, verify-pnl
// with balance evidence, a passing foundry PoC, the correlate kill chain
// composite, and one finding with an unknown weakness ID.
func fixtureFindings() []core.Finding {
	return []core.Finding{
		{
			ID:          "engine-evm-fingerprint",
			Title:       "Chain fingerprinted",
			Severity:    core.SevInfo,
			Confidence:  core.ConfConfirmed,
			Layer:       "L1",
			Weakness:    "BTV-L1-001",
			Description: "Chain identity established via JSON-RPC.",
			Evidence:    "chainId=31337 blockNumber=0 clientVersion=anvil/v1.9.0",
			Source:      "engine-evm",
		},
		{
			ID:          "engine-evm-map-oracles",
			Title:       "Oracle dependency: latestAnswer()",
			Severity:    core.SevMedium,
			Confidence:  core.ConfHigh,
			Layer:       "L2",
			Weakness:    "BTV-L2-003",
			Description: "Bytecode references latestAnswer() (Chainlink-style aggregator (legacy)).",
			Evidence:    "address=0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512 selector=0x50d25bcd",
			Source:      "engine-evm",
		},
		{
			ID:          "engine-evm-simulate-call",
			Title:       "Call succeeds in simulation: borrow(uint256)",
			Severity:    core.SevMedium,
			Confidence:  core.ConfConfirmed,
			Layer:       "L2",
			Description: "eth_call with storage overrides returned successfully.",
			Evidence:    "to=0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512 calldata=0xc5ebeaec result=0x",
			Source:      "engine-evm",
		},
		{
			ID:          "engine-evm-verify-pnl",
			Title:       "Exploit profit verified",
			Severity:    core.SevCritical,
			Confidence:  core.ConfConfirmed,
			Layer:       "L5",
			Description: "The tracked address gained balance over the exploit window.",
			Evidence:    "attacker=0x70997970C51812dc3A010C7d01b50e0d17dc79C8 balance@0=10000000000000000000000wei balance@6=10014999935592435371203wei",
			Source:      "engine-evm",
		},
		{
			ID:          "foundry-poc-test/Exploit.t.sol:ExploitTest-test_poc_oracle_manipulation_drains_vault()",
			Title:       "PoC passed: test_poc_oracle_manipulation_drains_vault()",
			Severity:    core.SevCritical,
			Confidence:  core.ConfConfirmed,
			Layer:       "L2",
			Weakness:    "BTV-L2-003",
			Evidence:    "forge test --json success",
			PoC:         "cd corpus/fixtures/naive-oracle-vault && forge test -m test_poc_oracle_manipulation_drains_vault()",
			Source:      "foundry",
		},
		{
			ID:          "engine-evm-unknown-probe",
			Title:       "Unknown-shape probe finding",
			Severity:    core.SevLow,
			Confidence:  core.ConfLow,
			Layer:       "L9",
			Weakness:    "BTV-L9-999",
			Description: "A finding whose weakness ID is not in the taxonomy.",
			Source:      "engine-evm",
		},
		{
			ID:          "killchain-oracle-manipulation",
			Title:       "End-to-end oracle manipulation kill chain",
			Severity:    core.SevCritical,
			Confidence:  core.ConfConfirmed,
			Description: "Composite narrative emitted by correlate.",
			Source:      "correlate",
		},
	}
}

func fixtureChains() []correlate.KillChain {
	return []correlate.KillChain{
		{
			ID:       "killchain-oracle-manipulation",
			Title:    "End-to-end oracle manipulation kill chain",
			Severity: core.SevCritical,
			Description: "Findings compose into a single compromise narrative: the BTV-L2-003 weakness was " +
				"identified, its exploit premise confirmed by state-override simulation, and profit verified on-chain.",
			Stages: []correlate.Stage{
				{Description: "Weakness identified: Oracle dependency: latestAnswer()", FindingID: "engine-evm-map-oracles", Layer: "L2"},
				{Description: "Exploit premise confirmed by simulation (no transaction broadcast)", FindingID: "engine-evm-simulate-call", Layer: "L2"},
				{Description: "Exploit executed on-chain and profit verified", FindingID: "engine-evm-verify-pnl", Layer: "L5"},
			},
			FinancialImpactWei: "14999935592435371203",
			FinancialImpactEth: "14.999936",
		},
	}
}

func renderEngagement(t *testing.T, findings []core.Finding, chains []correlate.KillChain, opts EngagementOptions) string {
	t.Helper()
	if opts.Taxonomy == nil {
		opts.Taxonomy = testTaxonomy(t)
	}
	if opts.Date.IsZero() {
		opts.Date = time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	}
	var buf bytes.Buffer
	if err := EngagementMarkdown(&buf, findings, chains, opts); err != nil {
		t.Fatalf("EngagementMarkdown: %v", err)
	}
	return buf.String()
}

func TestEngagementMarkdownAuthorizationAndHeader(t *testing.T) {
	out := renderEngagement(t, fixtureFindings(), fixtureChains(), EngagementOptions{
		Title:       "Vault Labs — Security Engagement Report",
		ToolVersion: "0.1.0",
		Target:      fixtureTarget(),
		SarifPath:   "runs/campaigns/x/findings.sarif",
	})

	for _, want := range []string{
		"# Vault Labs — Security Engagement Report",
		"BlockTack v0.1.0",
		"**Target**: naive-oracle-vault-lab — evm / local (chain ID 31337)",
		"## Scope & Authorization",
		"**Authorized by**: Dr. Elena Voss, CISO — Vault Labs Inc.",
		"naive-oracle-vault fixture on a local anvil instance",
		"**Expires**: 2027-12-31",
		"NaiveOracleVault (`0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512`)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing authorization/header line %q", want)
		}
	}
}

func TestEngagementMarkdownExecSummaryAndKillChain(t *testing.T) {
	out := renderEngagement(t, fixtureFindings(), fixtureChains(), EngagementOptions{
		Target: fixtureTarget(),
	})

	// 7 findings total, but the killchain composite is rendered in the
	// kill chain section, so 6 atomic findings are counted.
	if !strings.Contains(out, "**6 findings** (2 critical, 2 medium, 1 low, 1 info)") {
		t.Errorf("exec summary finding counts wrong:\n%s", out)
	}
	if !strings.Contains(out, "**1 kill chain**") {
		t.Errorf("exec summary missing kill chain count")
	}
	if !strings.Contains(out, "**verified financial impact of 14.999936 ETH**") {
		t.Errorf("exec summary missing verified financial impact")
	}
	if !strings.Contains(out, "within the authorization granted by Dr. Elena Voss") {
		t.Errorf("exec summary missing scope & authorization statement")
	}

	// Kill chain section with stages and financial impact.
	for _, want := range []string{
		"## Kill Chains",
		"### 1. End-to-end oracle manipulation kill chain (critical)",
		"Weakness identified: Oracle dependency: latestAnswer()",
		"`engine-evm-verify-pnl`",
		"**Verified financial impact**: 14.999936 ETH (14999935592435371203 wei)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("kill chain section missing %q", want)
		}
	}
}

func TestEngagementMarkdownDetailedFindings(t *testing.T) {
	out := renderEngagement(t, fixtureFindings(), fixtureChains(), EngagementOptions{
		Target: fixtureTarget(),
	})

	// Severity grouping, most severe first.
	crit := strings.Index(out, "### Critical")
	med := strings.Index(out, "### Medium")
	info := strings.Index(out, "### Info")
	if crit < 0 || med < 0 || info < 0 || !(crit < med && med < info) {
		t.Errorf("severity groups missing or out of order (crit=%d med=%d info=%d)", crit, med, info)
	}

	// Taxonomy-enriched weakness line and remediation for BTV-L2-003.
	if !strings.Contains(out, "- **Weakness**: `BTV-L2-003` — Manipulable price oracle (layer L2)") {
		t.Errorf("missing taxonomy weakness line for BTV-L2-003")
	}
	if !strings.Contains(out, "circuit breaker") {
		t.Errorf("missing remediation text from taxonomy for BTV-L2-003")
	}

	// Evidence, PoC, confidence and source are rendered.
	for _, want := range []string{
		"balance@0=10000000000000000000000wei balance@6=10014999935592435371203wei",
		"forge test -m test_poc_oracle_manipulation_drains_vault()",
		"- **Confidence**: confirmed",
		"- **Source**: engine-evm",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("detailed findings missing %q", want)
		}
	}

	// The killchain composite must not be rendered as an atomic finding:
	// exactly one occurrence of its title, inside the Kill Chains section.
	if n := strings.Count(out, "End-to-end oracle manipulation kill chain"); n != 1 {
		t.Errorf("kill chain composite leaked into detailed findings (%d title occurrences)", n)
	}
}

func TestEngagementMarkdownUnknownWeaknessDegrades(t *testing.T) {
	out := renderEngagement(t, fixtureFindings(), fixtureChains(), EngagementOptions{
		Target: fixtureTarget(),
	})

	if !strings.Contains(out, "`BTV-L9-999` (not in the BlockTack taxonomy)") {
		t.Errorf("unknown weakness ID not rendered gracefully")
	}
	// The remediation summary should include the unknown ID with no
	// remediation text (an em dash placeholder), not a crash or a blank row.
	if !strings.Contains(out, "| `BTV-L9-999` (not in the BlockTack taxonomy) | 1 | low | — |") {
		t.Errorf("remediation summary row for unknown weakness ID wrong:\n%s", out)
	}
}

func TestEngagementMarkdownRemediationSummary(t *testing.T) {
	out := renderEngagement(t, fixtureFindings(), fixtureChains(), EngagementOptions{
		Target: fixtureTarget(),
	})

	if !strings.Contains(out, "## Remediation Summary") {
		t.Fatalf("missing remediation summary section")
	}
	// BTV-L2-003: 2 occurrences, max severity critical → score 2*5=10,
	// ranked above BTV-L1-001 (1*1) and BTV-L9-999 (1*2).
	sumStart := strings.Index(out, "## Remediation Summary")
	if sumStart < 0 {
		t.Fatalf("missing remediation summary section")
	}
	summary := out[sumStart:]
	if !strings.Contains(summary, "| `BTV-L2-003` — Manipulable price oracle | 2 | critical |") {
		t.Errorf("remediation summary missing BTV-L2-003 row")
	}
	l2 := strings.Index(summary, "`BTV-L2-003` — Manipulable price oracle | 2")
	l1 := strings.Index(summary, "`BTV-L1-001`")
	if l2 < 0 || l1 < 0 || l1 < l2 {
		t.Errorf("remediation summary not sorted by count × severity")
	}
}

func TestEngagementMarkdownNoTargetNoChains(t *testing.T) {
	// No target file: the report must still render, with a notice about
	// the missing authorization record.
	out := renderEngagement(t, fixtureFindings()[:4], nil, EngagementOptions{})
	if !strings.Contains(out, "No authorization record was supplied") {
		t.Errorf("missing no-authorization notice")
	}
	if strings.Contains(out, "## Kill Chains") {
		t.Errorf("kill chains section rendered with no chains")
	}
	if !strings.Contains(out, "No cross-layer kill chains were composed") {
		t.Errorf("exec summary should state that no chains were composed")
	}
}

func TestEngagementMarkdownNilTaxonomyDegrades(t *testing.T) {
	// A nil taxonomy with an unloadable path must not fail; weakness IDs
	// render raw without names or remediation.
	var buf bytes.Buffer
	opts := EngagementOptions{
		TaxonomyPath: "/nonexistent/taxonomy.yaml",
		Date:         time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC),
	}
	if err := EngagementMarkdown(&buf, fixtureFindings(), nil, opts); err != nil {
		t.Fatalf("EngagementMarkdown with nil taxonomy: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "`BTV-L2-003` (not in the BlockTack taxonomy)") {
		t.Errorf("nil taxonomy should degrade to raw weakness IDs")
	}
	if strings.Contains(out, "circuit breaker") {
		t.Errorf("nil taxonomy should not render remediation text")
	}
}

// TestTaxonomyRemediationComplete verifies the shipped taxonomy file
// carries remediation guidance for every weakness.
func TestTaxonomyRemediationComplete(t *testing.T) {
	tx := testTaxonomy(t)
	total := 0
	for _, l := range tx.Layers {
		for _, w := range l.Weaknesses {
			if strings.TrimSpace(w.Remediation) == "" {
				t.Errorf("%s (%s): missing remediation", w.ID, w.Name)
			}
			total++
		}
	}
	if total < 40 {
		t.Errorf("expected the full taxonomy (52 weaknesses), got %d", total)
	}
}
