// Engagement-grade report rendering: a deliverable a client can receive,
// not just a findings dump. EngagementMarkdown composes the header with
// authorization context, a data-generated executive summary, kill chains,
// detailed findings with taxonomy remediation, a ranked remediation
// summary, and a methodology appendix.
package report

import (
	"fmt"
	"io"
	"math/big"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/blocktack/blocktack/internal/core"
	"github.com/blocktack/blocktack/internal/correlate"
)

// EngagementOptions carries the context an engagement report needs: who
// authorized the assessment, what was in scope, and where the
// machine-readable artifacts live.
type EngagementOptions struct {
	// Title of the deliverable. Defaults to "BlockTack Engagement Report".
	Title string
	// ToolVersion is the BlockTack version that produced the findings.
	ToolVersion string
	// Target is the assessed system (optional). When present, its
	// authorization block and in-scope assets are rendered in the header.
	Target *core.Target
	// Date is the report date; defaults to time.Now().UTC().
	Date time.Time
	// Taxonomy classifies weakness IDs and carries remediation text.
	// When nil, it is loaded from TaxonomyPath or the default location;
	// if that fails too, weakness IDs render without names or remediation.
	Taxonomy     *core.Taxonomy
	TaxonomyPath string
	// SarifPath references the SARIF artifact for machine-readable intake.
	SarifPath string
	// FindingsFiles are the findings JSON files merged into this report,
	// listed in the methodology appendix.
	FindingsFiles []string
}

// severityOrder is the display order for severity groups, most severe first.
var severityOrder = []core.Severity{core.SevCritical, core.SevHigh, core.SevMedium, core.SevLow, core.SevInfo}

// EngagementMarkdown writes an engagement-grade markdown report.
func EngagementMarkdown(w io.Writer, findings []core.Finding, chains []correlate.KillChain, opts EngagementOptions) error {
	if opts.Title == "" {
		opts.Title = "BlockTack Engagement Report"
	}
	if opts.Date.IsZero() {
		opts.Date = time.Now().UTC()
	}
	tx := opts.Taxonomy
	if tx == nil {
		path := opts.TaxonomyPath
		if path == "" {
			path = core.DefaultTaxonomyPath()
		}
		if loaded, err := core.LoadTaxonomy(path); err == nil {
			tx = loaded
		}
	}

	// Kill chain composites emitted by correlate are narratives, not
	// atomic findings; when chains are rendered in their own section they
	// are excluded from the findings count and detailed listing.
	atomic := make([]core.Finding, 0, len(findings))
	for _, f := range findings {
		f.Normalize()
		if len(chains) > 0 && strings.HasPrefix(f.ID, "killchain-") {
			continue
		}
		atomic = append(atomic, f)
	}
	sortFindings(atomic)

	writeHeader(w, atomic, chains, opts, tx)
	writeExecSummary(w, atomic, chains, opts, tx)
	writeKillChains(w, chains)
	writeFindings(w, atomic, tx)
	writeRemediationSummary(w, atomic, tx)
	writeAppendix(w, atomic, chains, opts, tx)
	return nil
}

// sortFindings orders findings most severe first, then by layer.
func sortFindings(fs []core.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		ri, rj := core.SeverityRank(fs[i].Severity), core.SeverityRank(fs[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return fs[i].Layer < fs[j].Layer
	})
}

func writeHeader(w io.Writer, findings []core.Finding, chains []correlate.KillChain, opts EngagementOptions, tx *core.Taxonomy) {
	fmt.Fprintf(w, "# %s\n\n", opts.Title)

	fmt.Fprint(w, "**Prepared by**: BlockTack")
	if opts.ToolVersion != "" {
		fmt.Fprintf(w, " v%s", opts.ToolVersion)
	}
	fmt.Fprint(w, " (automated adversary simulation platform)\n")
	fmt.Fprintf(w, "**Date**: %s\n", opts.Date.Format("2006-01-02"))
	if opts.Target != nil {
		fmt.Fprintf(w, "**Target**: %s", opts.Target.Name)
		if label := chainLabel(opts.Target); label != "" {
			fmt.Fprintf(w, " — %s", label)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "**Findings**: %d across %d severity levels", len(findings), countSeverityLevels(findings))
	if len(chains) > 0 {
		fmt.Fprintf(w, ", %d kill chain%s", len(chains), plural(len(chains)))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w)

	// Scope & authorization.
	fmt.Fprint(w, "## Scope & Authorization\n\n")
	tgt := opts.Target
	if tgt == nil || !tgt.Authorization.Declared {
		fmt.Fprint(w, "> No authorization record was supplied with this report. Confirm the\n")
		fmt.Fprint(w, "> rules of engagement directly with the engagement owner before\n")
		fmt.Fprint(w, "> acting on any finding below.\n\n")
		return
	}
	auth := tgt.Authorization
	fmt.Fprint(w, "This assessment was conducted under a declared authorization:\n\n")
	fmt.Fprintf(w, "- **Authorized by**: %s\n", auth.AuthorizedBy)
	fmt.Fprintf(w, "- **Scope**: %s\n", auth.Scope)
	if auth.Expires.IsZero() {
		fmt.Fprint(w, "- **Expires**: not specified\n")
	} else if auth.Expires.Before(opts.Date) {
		fmt.Fprintf(w, "- **Expires**: %s — **WARNING: authorization expired before the report date**\n",
			auth.Expires.Format("2006-01-02"))
	} else {
		fmt.Fprintf(w, "- **Expires**: %s\n", auth.Expires.Format("2006-01-02"))
	}
	if len(tgt.Contracts) > 0 {
		items := make([]string, 0, len(tgt.Contracts))
		for _, c := range tgt.Contracts {
			s := c.Name
			if c.Address != "" {
				s += " (`" + c.Address + "`)"
			}
			items = append(items, s)
		}
		fmt.Fprintf(w, "- **Contracts in scope**: %s\n", strings.Join(items, ", "))
	}
	if len(tgt.Endpoints) > 0 {
		items := make([]string, 0, len(tgt.Endpoints))
		for _, e := range tgt.Endpoints {
			items = append(items, fmt.Sprintf("%s (%s, `%s`)", e.Name, e.Role, e.URL))
		}
		fmt.Fprintf(w, "- **Endpoints in scope**: %s\n", strings.Join(items, ", "))
	}
	fmt.Fprintln(w)
}

// chainLabel renders the target's chain context, e.g. "evm / mainnet-fork (chain ID 1)".
func chainLabel(t *core.Target) string {
	var parts []string
	if t.Chain.Type != "" {
		parts = append(parts, t.Chain.Type)
	}
	if t.Chain.Network != "" {
		parts = append(parts, t.Chain.Network)
	}
	label := strings.Join(parts, " / ")
	if t.Chain.ChainID != 0 {
		if label != "" {
			label += " "
		}
		label += fmt.Sprintf("(chain ID %d)", t.Chain.ChainID)
	}
	return label
}

func countSeverityLevels(findings []core.Finding) int {
	seen := map[core.Severity]bool{}
	for _, f := range findings {
		seen[core.NormalizeSeverity(f.Severity)] = true
	}
	return len(seen)
}

// severityBreakdown renders "2 critical, 1 high" style counts.
func severityBreakdown(findings []core.Finding) string {
	counts := map[core.Severity]int{}
	for _, f := range findings {
		counts[core.NormalizeSeverity(f.Severity)]++
	}
	var parts []string
	for _, s := range severityOrder {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	return strings.Join(parts, ", ")
}

func writeExecSummary(w io.Writer, findings []core.Finding, chains []correlate.KillChain, opts EngagementOptions, tx *core.Taxonomy) {
	fmt.Fprint(w, "## Executive Summary\n\n")

	targetName := "the assessed system"
	if opts.Target != nil && opts.Target.Name != "" {
		targetName = "**" + opts.Target.Name + "**"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "On %s, BlockTack executed an authorized adversary simulation against %s and recorded **%d findings**",
		opts.Date.Format("2006-01-02"), targetName, len(findings))
	if b := severityBreakdown(findings); b != "" {
		fmt.Fprintf(&sb, " (%s)", b)
	}
	sb.WriteString(". ")
	if len(chains) > 0 {
		fmt.Fprintf(&sb, "The findings compose into **%d kill chain%s** — cross-layer compromise narratives assembled from individual findings that no single tool could see. ",
			len(chains), plural(len(chains)))
	} else {
		sb.WriteString("No cross-layer kill chains were composed from these findings. ")
	}
	if total, ok := totalImpactWei(chains); ok {
		fmt.Fprintf(&sb, "The executed chains carry a **verified financial impact of %s ETH** — profit measured on-chain, not estimated. ", formatEth(total))
	}
	if top := topWeaknesses(findings, tx, 3); len(top) > 0 {
		fmt.Fprintf(&sb, "The most prevalent weakness classes were %s. ", strings.Join(top, "; "))
	}
	sb.WriteString("Every weakness class observed carries concrete remediation guidance, ranked by prevalence and severity in the Remediation Summary below.")
	fmt.Fprintf(w, "%s\n\n", sb.String())

	if opts.Target != nil && opts.Target.Authorization.Declared {
		fmt.Fprintf(w, "**Scope & authorization**: all activity described in this report was performed within the authorization granted by %s and limited to the declared scope; no systems outside it were contacted.\n\n",
			opts.Target.Authorization.AuthorizedBy)
	}
}

// topWeaknesses renders "BTV-L2-003 Manipulable price oracle (2 occurrences)".
func topWeaknesses(findings []core.Finding, tx *core.Taxonomy, n int) []string {
	counts := map[string]int{}
	maxRank := map[string]int{}
	for _, f := range findings {
		if f.Weakness == "" {
			continue
		}
		counts[f.Weakness]++
		if r := core.SeverityRank(f.Severity); r > maxRank[f.Weakness] {
			maxRank[f.Weakness] = r
		}
	}
	ids := make([]string, 0, len(counts))
	for id := range counts {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if counts[ids[i]] != counts[ids[j]] {
			return counts[ids[i]] > counts[ids[j]]
		}
		if maxRank[ids[i]] != maxRank[ids[j]] {
			return maxRank[ids[i]] > maxRank[ids[j]]
		}
		return ids[i] < ids[j]
	})
	var out []string
	for _, id := range ids {
		if len(out) >= n {
			break
		}
		name := ""
		if wk, _, ok := weaknessWithLayer(tx, id); ok {
			name = " " + wk.Name
		}
		out = append(out, fmt.Sprintf("`%s`%s (%d occurrence%s)",
			id, name, counts[id], plural(counts[id])))
	}
	return out
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func writeKillChains(w io.Writer, chains []correlate.KillChain) {
	if len(chains) == 0 {
		return
	}
	fmt.Fprint(w, "## Kill Chains\n\n")
	fmt.Fprint(w, "Kill chains are cross-layer compromise narratives composed from individual\n")
	fmt.Fprint(w, "findings by correlation analysis. Each stage links to the finding that\n")
	fmt.Fprint(w, "established it.\n\n")
	for i, c := range chains {
		fmt.Fprintf(w, "### %d. %s (%s)\n\n", i+1, c.Title, c.Severity)
		if c.Description != "" {
			fmt.Fprintf(w, "%s\n\n", c.Description)
		}
		fmt.Fprint(w, "| Stage | Layer | Finding |\n")
		fmt.Fprint(w, "|---|---|---|\n")
		for _, s := range c.Stages {
			layer := s.Layer
			if layer == "" {
				layer = "—"
			}
			fmt.Fprintf(w, "| %s | %s | `%s` |\n", mdEscape(s.Description), layer, s.FindingID)
		}
		fmt.Fprintln(w)
		if c.FinancialImpactEth != "" || c.FinancialImpactWei != "" {
			eth := c.FinancialImpactEth
			if eth == "" {
				if wei, ok := new(big.Int).SetString(c.FinancialImpactWei, 10); ok {
					eth = formatEth(wei)
				}
			}
			fmt.Fprintf(w, "**Verified financial impact**: %s ETH (%s wei)\n\n", eth, c.FinancialImpactWei)
		}
	}
}

func writeFindings(w io.Writer, findings []core.Finding, tx *core.Taxonomy) {
	fmt.Fprint(w, "## Detailed Findings\n\n")
	if len(findings) == 0 {
		fmt.Fprint(w, "No findings were recorded.\n\n")
		return
	}
	current := core.Severity("(none)")
	for _, f := range findings {
		if f.Severity != current {
			current = f.Severity
			fmt.Fprintf(w, "### %s\n\n", capitalize(string(current)))
		}
		fmt.Fprintf(w, "#### %s\n\n", f.Title)
		fmt.Fprintf(w, "- **Finding ID**: `%s`\n", f.ID)
		var remediation string
		if f.Weakness != "" {
			if wk, layer, ok := weaknessWithLayer(tx, f.Weakness); ok {
				fmt.Fprintf(w, "- **Weakness**: `%s` — %s (layer %s)\n", wk.ID, wk.Name, layer)
				remediation = wk.Remediation
			} else {
				fmt.Fprintf(w, "- **Weakness**: `%s` (not in the BlockTack taxonomy)\n", f.Weakness)
			}
		}
		if f.Layer != "" {
			fmt.Fprintf(w, "- **Layer**: %s\n", f.Layer)
		}
		fmt.Fprintf(w, "- **Severity**: %s\n", f.Severity)
		fmt.Fprintf(w, "- **Confidence**: %s\n", f.Confidence)
		if f.Target != "" {
			fmt.Fprintf(w, "- **Component**: %s\n", f.Target)
		}
		if f.Source != "" {
			fmt.Fprintf(w, "- **Source**: %s\n", f.Source)
		}
		fmt.Fprintln(w)
		if f.Description != "" {
			fmt.Fprintf(w, "%s\n\n", f.Description)
		}
		if remediation != "" {
			fmt.Fprintf(w, "**Remediation**: %s\n\n", remediation)
		}
		if f.Evidence != "" {
			fmt.Fprintf(w, "> **Evidence**: `%s`\n\n", f.Evidence)
		}
		if f.PoC != "" {
			fmt.Fprintf(w, "**Reproduce (PoC)**: `%s`\n\n", f.PoC)
		}
	}
}

func writeRemediationSummary(w io.Writer, findings []core.Finding, tx *core.Taxonomy) {
	fmt.Fprint(w, "## Remediation Summary\n\n")
	fmt.Fprint(w, "Weakness classes observed in this assessment, ranked by occurrence count\n")
	fmt.Fprint(w, "× highest observed severity.\n\n")

	type row struct {
		id, name, remediation string
		count, maxRank        int
		maxSeverity           core.Severity
	}
	rows := map[string]*row{}
	var order []string
	for _, f := range findings {
		if f.Weakness == "" {
			continue
		}
		r, ok := rows[f.Weakness]
		if !ok {
			r = &row{id: f.Weakness, maxRank: -1}
			rows[f.Weakness] = r
			order = append(order, f.Weakness)
		}
		r.count++
		if rank := core.SeverityRank(f.Severity); rank > r.maxRank {
			r.maxRank = rank
			r.maxSeverity = core.NormalizeSeverity(f.Severity)
		}
	}
	for _, id := range order {
		if wk, _, ok := weaknessWithLayer(tx, id); ok {
			rows[id].name = wk.Name
			rows[id].remediation = wk.Remediation
		}
	}
	sort.Slice(order, func(i, j int) bool {
		a, b := rows[order[i]], rows[order[j]]
		sa, sb := a.count*a.maxRank, b.count*b.maxRank
		if sa != sb {
			return sa > sb
		}
		return a.id < b.id
	})

	fmt.Fprint(w, "| Weakness | Occurrences | Highest severity | Remediation |\n")
	fmt.Fprint(w, "|---|---|---|---|\n")
	for _, id := range order {
		r := rows[id]
		label := "`" + r.id + "`"
		if r.name != "" {
			label += " — " + r.name
		} else {
			label += " (not in the BlockTack taxonomy)"
		}
		rem := r.remediation
		if rem == "" {
			rem = "—"
		}
		fmt.Fprintf(w, "| %s | %d | %s | %s |\n", label, r.count, r.maxSeverity, mdEscape(rem))
	}
	fmt.Fprintln(w)
}

func writeAppendix(w io.Writer, findings []core.Finding, chains []correlate.KillChain, opts EngagementOptions, tx *core.Taxonomy) {
	fmt.Fprint(w, "## Appendix\n\n")
	fmt.Fprint(w, "### Methodology\n\n")
	fmt.Fprint(w, "Findings were produced by the following BlockTack sources:\n\n")
	sourceCounts := map[string]int{}
	var sources []string
	for _, f := range findings {
		if f.Source == "" {
			continue
		}
		if _, ok := sourceCounts[f.Source]; !ok {
			sources = append(sources, f.Source)
		}
		sourceCounts[f.Source]++
	}
	sort.Strings(sources)
	for _, s := range sources {
		fmt.Fprintf(w, "- `%s`: %d finding(s)\n", s, sourceCounts[s])
	}
	fmt.Fprintln(w)
	fmt.Fprint(w, "Sources span static analysis adapters, on-chain simulation engines,\n")
	fmt.Fprint(w, "proof-of-concept execution, and cross-layer correlation. Severity follows\n")
	fmt.Fprint(w, "BlockTack's crypto-adapted scale (critical = direct loss of funds or chain\n")
	fmt.Fprint(w, "compromise); confidence \"confirmed\" means an exploit was executed and\n")
	fmt.Fprint(w, "verified, not merely hypothesized. Weakness classes are drawn from the\n")
	fmt.Fprint(w, "BlockTack weakness taxonomy (L0–L5); remediation text is advisory guidance\n")
	fmt.Fprint(w, "to be validated against the target's architecture.\n")
	if len(chains) > 0 {
		fmt.Fprint(w, "Kill chain composites emitted by correlation are reported in the Kill\n")
		fmt.Fprint(w, "Chains section rather than as atomic findings.\n")
	}
	fmt.Fprintln(w)

	if opts.SarifPath != "" || len(opts.FindingsFiles) > 0 {
		fmt.Fprint(w, "### Machine-Readable Artifacts\n\n")
		if opts.SarifPath != "" {
			if _, err := os.Stat(opts.SarifPath); err == nil {
				fmt.Fprintf(w, "- SARIF 2.1.0 (for CI and findings-management intake): `%s`\n", opts.SarifPath)
			} else {
				fmt.Fprintf(w, "- SARIF 2.1.0: `%s` (not found at this path when the report was rendered)\n", opts.SarifPath)
			}
		}
		for _, f := range opts.FindingsFiles {
			fmt.Fprintf(w, "- Findings JSON: `%s`\n", f)
		}
		fmt.Fprintln(w)
	}
}

// weaknessWithLayer looks up a weakness and the layer that contains it.
// A nil taxonomy degrades to not-found.
func weaknessWithLayer(tx *core.Taxonomy, id string) (core.Weakness, string, bool) {
	if tx == nil {
		return core.Weakness{}, "", false
	}
	for _, l := range tx.Layers {
		for _, wk := range l.Weaknesses {
			if wk.ID == id {
				return wk, l.ID, true
			}
		}
	}
	return core.Weakness{}, "", false
}

// totalImpactWei sums the verified profit across chains.
func totalImpactWei(chains []correlate.KillChain) (*big.Int, bool) {
	total := new(big.Int)
	any := false
	for _, c := range chains {
		if c.FinancialImpactWei == "" {
			continue
		}
		v, ok := new(big.Int).SetString(c.FinancialImpactWei, 10)
		if !ok {
			continue
		}
		total.Add(total, v)
		any = true
	}
	return total, any
}

// formatEth renders a wei amount as ETH with sensible precision.
func formatEth(wei *big.Int) string {
	eth := new(big.Float).SetPrec(256).Quo(
		new(big.Float).SetInt(wei),
		new(big.Float).SetInt(big.NewInt(1e18)),
	)
	return strings.TrimRight(strings.TrimRight(eth.Text('f', 6), "0"), ".")
}

// mdEscape makes text safe for a markdown table cell.
func mdEscape(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
