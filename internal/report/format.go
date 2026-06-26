package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/kanywst/spiffe-compliance-checker/internal/spec"
)

// Format selects how a Report is rendered.
type Format string

const (
	// FormatText is the default human-readable, optionally-colored report.
	FormatText Format = "text"
	// FormatJSON is a stable machine-readable object for automation.
	FormatJSON Format = "json"
	// FormatSARIF is SARIF 2.1.0, consumable by GitHub Code Scanning and
	// other static-analysis aggregators.
	FormatSARIF Format = "sarif"
)

// ParseFormat validates a --format value.
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case FormatText, FormatJSON, FormatSARIF:
		return Format(s), nil
	default:
		return "", fmt.Errorf("unknown format %q (want text, json, or sarif)", s)
	}
}

// Render writes the report to w in the requested format. Text rendering keeps
// the existing TTY-aware behaviour; json and sarif are deterministic and never
// colored, so they are safe to redirect into files or upload steps.
func (r *Report) Render(w io.Writer, f Format) error {
	switch f {
	case FormatJSON:
		return r.WriteJSON(w)
	case FormatSARIF:
		return r.WriteSARIF(w)
	default:
		r.Write(w)
		return nil
	}
}

func severityString(s spec.Severity) string {
	if s == spec.SeveritySHOULD {
		return "SHOULD"
	}
	return "MUST"
}

func statusString(s Status) string {
	switch s {
	case StatusPass:
		return "pass"
	case StatusFail:
		return "fail"
	case StatusWarn:
		return "warn"
	default:
		return "unknown"
	}
}

// --- JSON ---

type jsonReport struct {
	Subject    string          `json:"subject,omitempty"`
	Summary    jsonSummary     `json:"summary"`
	Assertions []jsonAssertion `json:"assertions"`
}

type jsonSummary struct {
	Passed   int `json:"passed"`
	Failed   int `json:"failed"`
	Warnings int `json:"warnings"`
}

type jsonAssertion struct {
	Status   string `json:"status"`
	Spec     string `json:"spec"`
	Section  string `json:"section"`
	Severity string `json:"severity"`
	Text     string `json:"text"`
	Detail   string `json:"detail,omitempty"`
}

// WriteJSON renders the report as a single JSON object. The shape is stable
// and intended for jq/CI consumption; exit code still signals overall pass/fail.
func (r *Report) WriteJSON(w io.Writer) error {
	pass, fail, warn := r.counts()
	out := jsonReport{
		Subject:    r.Subject,
		Summary:    jsonSummary{Passed: pass, Failed: fail, Warnings: warn},
		Assertions: make([]jsonAssertion, 0, len(r.Assertions)),
	}
	for _, a := range r.Assertions {
		out.Assertions = append(out.Assertions, jsonAssertion{
			Status:   statusString(a.Status),
			Spec:     a.Clause.Spec,
			Section:  a.Clause.Section,
			Severity: severityString(a.Clause.Severity),
			Text:     a.Clause.Text,
			Detail:   a.Detail,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// --- SARIF 2.1.0 ---

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name,omitempty"`
	ShortDescription     sarifText         `json:"shortDescription"`
	HelpURI              string            `json:"helpUri,omitempty"`
	DefaultConfiguration sarifRuleConfig   `json:"defaultConfiguration"`
	Properties           map[string]string `json:"properties,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID  string    `json:"ruleId"`
	Level   string    `json:"level"`
	Message sarifText `json:"message"`
}

type sarifText struct {
	Text string `json:"text"`
}

const (
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	sarifToolURI = "https://github.com/kanywst/spiffe-compliance-checker"
	specBaseURI  = "https://github.com/spiffe/spiffe/blob/main/standards/"
)

// WriteSARIF renders the report as a SARIF 2.1.0 log. Only fail and warn
// assertions become results (SARIF reports problems, not satisfied checks);
// every distinct clause encountered is registered as a rule so consumers can
// resolve ruleId -> description. A fully compliant artifact yields an empty
// results array, which is valid SARIF.
func (r *Report) WriteSARIF(w io.Writer) error {
	rules := make([]sarifRule, 0)
	seenRule := make(map[string]bool)
	results := make([]sarifResult, 0)

	for _, a := range r.Assertions {
		id := ruleID(a.Clause)
		if !seenRule[id] {
			seenRule[id] = true
			level := "error"
			if a.Clause.Severity == spec.SeveritySHOULD {
				level = "warning"
			}
			rules = append(rules, sarifRule{
				ID:                   id,
				Name:                 a.Clause.Spec + " " + a.Clause.Section,
				ShortDescription:     sarifText{Text: a.Clause.Text},
				HelpURI:              specBaseURI + a.Clause.Spec,
				DefaultConfiguration: sarifRuleConfig{Level: level},
				Properties: map[string]string{
					"spec":     a.Clause.Spec,
					"section":  a.Clause.Section,
					"severity": severityString(a.Clause.Severity),
				},
			})
		}
		if a.Status == StatusPass {
			continue
		}
		level := "error"
		if a.Status == StatusWarn {
			level = "warning"
		}
		msg := a.Clause.Text
		if a.Detail != "" {
			msg += " (" + a.Detail + ")"
		}
		results = append(results, sarifResult{
			RuleID:  id,
			Level:   level,
			Message: sarifText{Text: msg},
		})
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "scc",
				InformationURI: sarifToolURI,
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// ruleID derives a stable, unique SARIF rule identifier from a clause. Clause
// text is unique across the table, so slugifying spec + section + text yields
// a deterministic id that survives reordering of the clause table.
func ruleID(c spec.Clause) string {
	specName := strings.TrimSuffix(c.Spec, ".md")
	return slug(specName) + "/" + slug(c.Section) + "/" + slug(c.Text)
}

// slug lowercases s and collapses every run of non-alphanumeric characters to
// a single dash, trimming leading/trailing dashes.
func slug(s string) string {
	var b strings.Builder
	prevDash := false
	for _, c := range strings.ToLower(s) {
		switch {
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			b.WriteRune(c)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}
