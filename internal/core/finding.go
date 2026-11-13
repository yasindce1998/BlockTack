package core

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// Severity ranks a finding's impact on a crypto-adapted scale.
type Severity string

const (
	SevCritical Severity = "critical" // direct loss of funds / chain compromise
	SevHigh     Severity = "high"     // exploitable with significant impact
	SevMedium   Severity = "medium"   // exploitable under specific conditions
	SevLow      Severity = "low"      // defense-in-depth issue
	SevInfo     Severity = "info"     // reconnaissance / informational
)

// Confidence describes how certain the finding is.
type Confidence string

const (
	ConfConfirmed Confidence = "confirmed" // exploit executed and verified
	ConfHigh      Confidence = "high"
	ConfMedium    Confidence = "medium"
	ConfLow       Confidence = "low"
)

// Finding is the single currency of BlockTack: every adapter, engine, and
// playbook step produces findings, and reports aggregate them.
type Finding struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence,omitempty"`
	Layer       string     `json:"layer,omitempty"`    // L0..L5 taxonomy layer
	Weakness    string     `json:"weakness,omitempty"` // taxonomy weakness ID, e.g. BTV-L2-003
	Description string     `json:"description,omitempty"`
	Evidence    string     `json:"evidence,omitempty"`
	Target      string     `json:"target,omitempty"` // component the finding applies to
	PoC         string     `json:"poc,omitempty"`    // command or path that reproduces the finding
	Source      string     `json:"source,omitempty"` // adapter/engine that produced it
	DetectedAt  time.Time  `json:"detectedAt,omitempty"`
}

// Normalize fills defaults and maps foreign severity vocabularies
// (e.g. SARIF levels) onto BlockTack severities.
func (f *Finding) Normalize() {
	if f.DetectedAt.IsZero() {
		f.DetectedAt = time.Now().UTC()
	}
	if f.Confidence == "" {
		f.Confidence = ConfMedium
	}
	if f.Severity == "" {
		f.Severity = SevInfo
	}
	f.Severity = NormalizeSeverity(f.Severity)
}

// NormalizeSeverity maps SARIF levels and common variants to severities.
func NormalizeSeverity(s Severity) Severity {
	switch s {
	case SevCritical, SevHigh, SevMedium, SevLow, SevInfo:
		return s
	case "error":
		return SevHigh
	case "warning":
		return SevMedium
	case "note":
		return SevLow
	case "none":
		return SevInfo
	default:
		return Severity(s)
	}
}

// SeverityRank returns a sortable rank, higher = more severe.
func SeverityRank(s Severity) int {
	switch NormalizeSeverity(s) {
	case SevCritical:
		return 5
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	default:
		return 1
	}
}

// LoadFindingsJSON reads a findings JSON array produced by any BlockTack
// command, adapter, or engine.
func LoadFindingsJSON(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read findings: %w", err)
	}
	var fs []Finding
	if err := json.Unmarshal(data, &fs); err != nil {
		return nil, fmt.Errorf("parse findings %s: %w", path, err)
	}
	for i := range fs {
		fs[i].Normalize()
	}
	return fs, nil
}

// SaveFindingsJSON writes a findings JSON array.
func SaveFindingsJSON(findings []Finding, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}

// WriteSARIF emits findings as a SARIF 2.1.0 log, the interchange format
// for adapters (Slither et al.) and CI integrations.
func WriteSARIF(w io.Writer, findings []Finding) error {
	results := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		ruleID := f.Weakness
		if ruleID == "" {
			ruleID = f.ID
		}
		msg := f.Title
		if f.Description != "" {
			msg = msg + ": " + f.Description
		}
		results = append(results, map[string]any{
			"ruleId": ruleID,
			"level":  sarifLevel(f.Severity),
			"message": map[string]any{
				"text": msg,
			},
			"properties": map[string]any{
				"blocktack": map[string]any{
					"id":         f.ID,
					"severity":   f.Severity,
					"confidence": f.Confidence,
					"layer":      f.Layer,
					"weakness":   f.Weakness,
					"target":     f.Target,
					"evidence":   f.Evidence,
					"poc":        f.PoC,
					"source":     f.Source,
				},
			},
		})
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":           "blocktack",
					"informationUri": "https://github.com/blocktack/blocktack",
				},
			},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func sarifLevel(s Severity) string {
	switch NormalizeSeverity(s) {
	case SevCritical, SevHigh:
		return "error"
	case SevMedium:
		return "warning"
	case SevLow:
		return "note"
	default:
		return "none"
	}
}

// ParseSARIFResults reads SARIF results (from any producer) into findings.
// BlockTack-specific fields are picked up from properties.blocktack when
// present; source names the producing tool.
func ParseSARIFResults(data []byte, source string) ([]Finding, error) {
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID     string `json:"ruleId"`
				Level      string `json:"level"`
				Message    struct {
					Text string `json:"text"`
				} `json:"message"`
				Properties struct {
					Blocktack struct {
						ID         string `json:"id"`
						Severity   string `json:"severity"`
						Confidence string `json:"confidence"`
						Layer      string `json:"layer"`
						Weakness   string `json:"weakness"`
						Target     string `json:"target"`
						Evidence   string `json:"evidence"`
						PoC        string `json:"poc"`
						Source     string `json:"source"`
					} `json:"blocktack"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse SARIF: %w", err)
	}
	var findings []Finding
	for _, run := range doc.Runs {
		for _, res := range run.Results {
			bt := res.Properties.Blocktack
			weakness := bt.Weakness
			if weakness == "" {
				weakness = res.RuleID
			}
			f := Finding{
				ID:          bt.ID,
				Title:       firstNonEmpty(truncate(res.Message.Text, 160), "finding from "+source),
				Severity:    Severity(firstNonEmpty(bt.Severity, res.Level)),
				Confidence:  Confidence(bt.Confidence),
				Layer:       bt.Layer,
				Weakness:    weakness,
				Evidence:    bt.Evidence,
				Target:      bt.Target,
				PoC:         bt.PoC,
				Source:      firstNonEmpty(bt.Source, source),
			}
			f.Normalize()
			if f.ID == "" {
				f.ID = fmt.Sprintf("%s-%d", f.Source, len(findings)+1)
			}
			findings = append(findings, f)
		}
	}
	return findings, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
