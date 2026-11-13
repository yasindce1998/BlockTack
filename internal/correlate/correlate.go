// Package correlate composes multi-layer findings into kill chains:
// the cross-layer narratives that individual tools cannot see. A medium
// oracle-dependency finding plus a simulation success plus a verified
// profit is not three findings — it is one end-to-end compromise.
package correlate

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/blocktack/blocktack/internal/core"
)

// Stage is one link in a kill chain, backed by a concrete finding.
type Stage struct {
	Description string `json:"description"`
	FindingID   string `json:"findingId"`
	Layer       string `json:"layer,omitempty"`
}

// KillChain is a composite narrative assembled from findings.
type KillChain struct {
	ID          string       `json:"id"`
	Title       string       `json:"title"`
	Severity    core.Severity `json:"severity"`
	Description string       `json:"description"`
	Stages      []Stage      `json:"stages"`
	// FinancialImpactWei is the verified profit extracted, parsed from
	// verify-pnl evidence, when the chain ends in a confirmed drain.
	FinancialImpactWei string `json:"financialImpactWei,omitempty"`
	FinancialImpactEth string `json:"financialImpactEth,omitempty"`
}

// Analyze inspects findings and returns composed kill chains.
func Analyze(findings []core.Finding) []KillChain {
	var chains []KillChain
	chains = append(chains, economicDrainChain(findings)...)
	chains = append(chains, nodeObservationChain(findings)...)
	chains = append(chains, offChainCredentialChain(findings)...)
	return chains
}

// has reports whether any finding matches the predicate.
func has(findings []core.Finding, pred func(core.Finding) bool) (core.Finding, bool) {
	for _, f := range findings {
		if pred(f) {
			return f, true
		}
	}
	return core.Finding{}, false
}

func byWeakness(w string) func(core.Finding) bool {
	return func(f core.Finding) bool { return f.Weakness == w }
}

func byID(id string) func(core.Finding) bool {
	return func(f core.Finding) bool { return f.ID == id }
}

func simulationSuccess(f core.Finding) bool {
	return f.ID == "engine-evm-simulate-call" && strings.Contains(f.Title, "succeeds")
}

func profitVerified(f core.Finding) bool {
	return f.ID == "engine-evm-verify-pnl" && strings.Contains(f.Title, "profit verified")
}

// economicDrainChain composes the flagship pattern: a weakness was
// found, confirmed by simulation, executed on-chain, and profited from.
func economicDrainChain(findings []core.Finding) []KillChain {
	type pattern struct {
		id       string
		title    string
		weakness string
	}
	patterns := []pattern{
		{id: "killchain-oracle-manipulation", title: "End-to-end oracle manipulation kill chain", weakness: "BTV-L2-003"},
		{id: "killchain-reentrancy-drain", title: "End-to-end reentrancy drain kill chain", weakness: "BTV-L2-001"},
	}
	var chains []KillChain
	for _, p := range patterns {
		weakness, hasWeakness := has(findings, byWeakness(p.weakness))
		if !hasWeakness {
			// Reentrancy also enters via the unchecked-call compiler signal.
			if p.weakness == "BTV-L2-001" {
				weakness, hasWeakness = has(findings, byWeakness("BTV-L2-005"))
			}
			if !hasWeakness {
				continue
			}
		}
		sim, hasSim := has(findings, simulationSuccess)
		profit, hasProfit := has(findings, profitVerified)

		chain := KillChain{
			ID:       p.id,
			Title:    p.title,
			Severity: core.SevMedium,
			Description: fmt.Sprintf(
				"Findings compose into a single compromise narrative: the %s weakness was "+
					"identified, its exploit premise confirmed by state-override simulation, "+
					"and (if executed) profit verified on-chain.", p.weakness),
			Stages: []Stage{{
				Description: fmt.Sprintf("Weakness identified: %s", weakness.Title),
				FindingID:   weakness.ID,
				Layer:       weakness.Layer,
			}},
		}
		if hasSim {
			chain.Stages = append(chain.Stages, Stage{
				Description: "Exploit premise confirmed by simulation (no transaction broadcast)",
				FindingID:   sim.ID,
				Layer:       sim.Layer,
			})
		}
		if hasProfit {
			chain.Severity = core.SevCritical
			chain.Stages = append(chain.Stages, Stage{
				Description: "Exploit executed on-chain and profit verified",
				FindingID:   profit.ID,
				Layer:       profit.Layer,
			})
			wei, ok := parseProfitWei(profit.Evidence)
			if ok {
				chain.FinancialImpactWei = wei.String()
				chain.FinancialImpactEth = formatEth(wei)
				chain.Description += fmt.Sprintf(
					" Verified financial impact: %s ETH extracted.", chain.FinancialImpactEth)
			}
		}
		chains = append(chains, chain)
	}
	return chains
}

// nodeObservationChain composes mempool/peer exposure into a
// surveillance-and-front-running narrative.
func nodeObservationChain(findings []core.Finding) []KillChain {
	mempool, hasMempool := has(findings, byID("nodeaudit-mempool-exposed"))
	txpoolRecon, hasTxpool := has(findings, byWeakness("BTV-L0-001"))
	peers, hasPeers := has(findings, byID("nodeaudit-peers-exposed"))
	if !hasMempool && !hasTxpool {
		return nil
	}
	source := mempool
	if !hasMempool {
		source = txpoolRecon
	}
	chain := KillChain{
		ID:       "killchain-node-surveillance",
		Title:    "Node surveillance kill chain",
		Severity: core.SevMedium,
		Description: "The node's mempool is readable by unauthenticated callers: every pending " +
			"transaction is a front-running/sandwich target (BTV-L5-004).",
		Stages: []Stage{{
			Description: "Mempool exposure confirmed",
			FindingID:   source.ID,
			Layer:       source.Layer,
		}},
	}
	if hasPeers {
		chain.Stages = append(chain.Stages, Stage{
			Description: "Peer topology exposed — eclipse attack planning is feasible (BTV-L1-002)",
			FindingID:   peers.ID,
			Layer:       peers.Layer,
		})
		chain.Title = "Node surveillance and eclipse-recon kill chain"
	}
	return []KillChain{chain}
}

// offChainCredentialChain composes exposed web secrets into a key-
// compromise narrative (the Multichain/Radiant/Bybit shape).
func offChainCredentialChain(findings []core.Finding) []KillChain {
	exposed, ok := has(findings, func(f core.Finding) bool {
		return f.ID == "webaudit-exposed-path" &&
			core.SeverityRank(f.Severity) >= core.SeverityRank(core.SevHigh)
	})
	if !ok {
		return nil
	}
	return []KillChain{{
		ID:       "killchain-credential-exposure",
		Title:    "Off-chain credential exposure kill chain",
		Severity: core.SevHigh,
		Description: "High-value secrets are served by the web root. In the historical incident " +
			"record (Multichain 2023, Radiant 2024, Bybit 2025), exposed or stolen off-chain " +
			"credentials — not contract bugs — were the direct cause of the largest losses. " +
			"Cross-reference what these credentials unlock (BTV-L4-004).",
		Stages: []Stage{{
			Description: exposed.Title,
			FindingID:   exposed.ID,
			Layer:       exposed.Layer,
		}},
	}}
}

// parseProfitWei extracts the balance delta from verify-pnl evidence:
// "attacker=0x.. balance@N=<wei>wei balance@M=<wei>wei".
func parseProfitWei(evidence string) (*big.Int, bool) {
	balances := []string{}
	for _, part := range strings.Fields(evidence) {
		if strings.HasPrefix(part, "balance@") {
			balances = append(balances, strings.TrimSuffix(strings.SplitN(part, "=", 2)[1], "wei"))
		}
	}
	if len(balances) < 2 {
		return nil, false
	}
	past, ok1 := new(big.Int).SetString(balances[0], 10)
	now, ok2 := new(big.Int).SetString(balances[len(balances)-1], 10)
	if !ok1 || !ok2 {
		return nil, false
	}
	delta := new(big.Int).Sub(now, past)
	if delta.Sign() <= 0 {
		return nil, false
	}
	return delta, true
}

// formatEth renders a wei amount as ETH with a sensible precision.
func formatEth(wei *big.Int) string {
	eth := new(big.Float).SetPrec(256).Quo(
		new(big.Float).SetInt(wei),
		new(big.Float).SetInt(big.NewInt(1e18)),
	)
	return strings.TrimRight(strings.TrimRight(eth.Text('f', 6), "0"), ".")
}
