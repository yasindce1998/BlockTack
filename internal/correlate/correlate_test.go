package correlate

import (
	"testing"

	"github.com/blocktack/blocktack/internal/core"
)

// oracleCampaignFindings mirrors the actual findings of the
// naive-oracle-vault campaign.
func oracleCampaignFindings() []core.Finding {
	return []core.Finding{
		{ID: "recon-client-fingerprint", Title: "Node client fingerprinted", Severity: core.SevInfo, Layer: "L1", Weakness: "BTV-L1-001"},
		{ID: "engine-evm-map-oracles", Title: "Oracle dependency: latestAnswer()", Severity: core.SevMedium, Layer: "L2", Weakness: "BTV-L2-003"},
		{ID: "engine-evm-simulate-call", Title: "Call succeeds in simulation: borrow(uint256)", Severity: core.SevMedium, Layer: "L2"},
		{ID: "engine-evm-verify-pnl", Title: "Exploit profit verified", Severity: core.SevCritical, Layer: "L5",
			Evidence: "attacker=0x7099 balance@0=10000000000000000000000wei balance@6=10014999935592435371203wei"},
		{ID: "foundry-poc-x", Title: "PoC passed: test_poc_oracle_manipulation_drains_vault()", Severity: core.SevCritical, Layer: "L2", Weakness: "BTV-L2-003"},
	}
}

func TestOracleKillChainComposes(t *testing.T) {
	chains := Analyze(oracleCampaignFindings())
	var chain *KillChain
	for i := range chains {
		if chains[i].ID == "killchain-oracle-manipulation" {
			chain = &chains[i]
		}
	}
	if chain == nil {
		t.Fatalf("expected oracle kill chain, got %+v", chains)
	}
	if chain.Severity != core.SevCritical {
		t.Errorf("severity = %s, want critical (profit was verified)", chain.Severity)
	}
	if len(chain.Stages) != 3 {
		t.Errorf("stages = %d, want 3 (weakness, simulation, profit)", len(chain.Stages))
	}
	if chain.FinancialImpactWei != "14999935592435371203" {
		t.Errorf("financialImpactWei = %s, want 14999935592435371203", chain.FinancialImpactWei)
	}
	if chain.FinancialImpactEth != "14.999936" {
		t.Errorf("financialImpactEth = %s, want 14.999936", chain.FinancialImpactEth)
	}
}

func TestReentrancyChainViaCompilerSignal(t *testing.T) {
	findings := []core.Finding{
		{ID: "foundry-build-warning", Title: "Compiler warning: unchecked low-level call", Severity: core.SevMedium, Layer: "L2", Weakness: "BTV-L2-005"},
		{ID: "engine-evm-simulate-call", Title: "Call succeeds in simulation: attack()", Severity: core.SevMedium, Layer: "L2"},
		{ID: "engine-evm-verify-pnl", Title: "Exploit profit verified", Severity: core.SevCritical, Layer: "L5",
			Evidence: "attacker=0xe7f1 balance@2=0wei balance@6=11000000000000000000wei"},
	}
	chains := Analyze(findings)
	found := false
	for _, c := range chains {
		if c.ID == "killchain-reentrancy-drain" {
			found = true
			if c.Severity != core.SevCritical {
				t.Errorf("severity = %s, want critical", c.Severity)
			}
			if c.FinancialImpactEth != "11" {
				t.Errorf("financialImpactEth = %s, want 11", c.FinancialImpactEth)
			}
		}
	}
	if !found {
		t.Fatalf("expected reentrancy kill chain, got %+v", chains)
	}
}

func TestUnverifiedPremiseIsMedium(t *testing.T) {
	findings := []core.Finding{
		{ID: "engine-evm-map-oracles", Title: "Oracle dependency: latestAnswer()", Severity: core.SevMedium, Layer: "L2", Weakness: "BTV-L2-003"},
		{ID: "engine-evm-simulate-call", Title: "Call succeeds in simulation: borrow(uint256)", Severity: core.SevMedium, Layer: "L2"},
	}
	chains := Analyze(findings)
	for _, c := range chains {
		if c.ID == "killchain-oracle-manipulation" {
			if c.Severity != core.SevMedium {
				t.Errorf("severity = %s, want medium without verified profit", c.Severity)
			}
			if c.FinancialImpactWei != "" {
				t.Errorf("unexpected financial impact on unverified chain")
			}
			return
		}
	}
	t.Fatal("expected oracle kill chain")
}

func TestNodeSurveillanceChain(t *testing.T) {
	findings := []core.Finding{
		{ID: "nodeaudit-mempool-exposed", Title: "Mempool exposed: 2 pending transactions visible", Severity: core.SevMedium, Layer: "L1", Weakness: "BTV-L1-009"},
		{ID: "nodeaudit-peers-exposed", Title: "Peer topology exposed: 10 peers", Severity: core.SevMedium, Layer: "L0", Weakness: "BTV-L0-002"},
	}
	chains := Analyze(findings)
	found := false
	for _, c := range chains {
		if c.ID == "killchain-node-surveillance" {
			found = true
			if len(c.Stages) != 2 {
				t.Errorf("stages = %d, want 2", len(c.Stages))
			}
		}
	}
	if !found {
		t.Fatalf("expected node surveillance chain, got %+v", chains)
	}
}

func TestCredentialExposureChain(t *testing.T) {
	findings := []core.Finding{
		{ID: "webaudit-exposed-path", Title: "Committed .env file served by the web root", Severity: core.SevHigh, Layer: "L4", Weakness: "BTV-L4-003"},
	}
	chains := Analyze(findings)
	if len(chains) != 1 || chains[0].ID != "killchain-credential-exposure" {
		t.Fatalf("expected credential exposure chain, got %+v", chains)
	}
	if chains[0].Severity != core.SevHigh {
		t.Errorf("severity = %s, want high", chains[0].Severity)
	}
}

func TestNoFalseChainsFromUnrelatedFindings(t *testing.T) {
	findings := []core.Finding{
		{ID: "recon-client-fingerprint", Title: "Node client fingerprinted", Severity: core.SevInfo, Layer: "L1"},
		{ID: "webaudit-plaintext", Title: "Plaintext HTTP", Severity: core.SevLow, Layer: "L4"},
	}
	if chains := Analyze(findings); len(chains) != 0 {
		t.Errorf("expected no chains, got %+v", chains)
	}
}

func TestParseProfitWeiMalformed(t *testing.T) {
	if _, ok := parseProfitWei("nonsense"); ok {
		t.Error("malformed evidence should not parse")
	}
	if _, ok := parseProfitWei("attacker=0x1 balance@0=100wei balance@6=50wei"); ok {
		t.Error("negative delta should not parse")
	}
}
