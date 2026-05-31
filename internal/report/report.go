// Package report aggregates the PASS/FAIL/WARN outcomes of compliance checks
// and renders them as a one-line-per-assertion text report.
package report

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/0-draft/spiffe-compliance-checker/internal/spec"
)

// Status is the outcome of evaluating one clause against an artifact.
type Status int

const (
	// StatusPass means the artifact satisfies the clause.
	StatusPass Status = iota
	// StatusFail means the artifact violates a MUST/MUST NOT clause.
	StatusFail
	// StatusWarn means the artifact violates a SHOULD/SHOULD NOT clause.
	StatusWarn
)

func (s Status) label() string {
	switch s {
	case StatusPass:
		return "PASS"
	case StatusFail:
		return "FAIL"
	case StatusWarn:
		return "WARN"
	default:
		return "?"
	}
}

// Assertion is one evaluated clause.
type Assertion struct {
	Status Status
	Clause spec.Clause
	Detail string // optional supporting detail (the offending value, parsed observation, etc.)
}

// Report collects assertions in evaluation order.
type Report struct {
	Assertions []Assertion
}

// Pass records a satisfied clause.
func (r *Report) Pass(c spec.Clause, detail string) {
	r.Assertions = append(r.Assertions, Assertion{StatusPass, c, detail})
}

// Fail records a violated clause. If the clause severity is SHOULD it is
// downgraded to a warning so exit code stays zero.
func (r *Report) Fail(c spec.Clause, detail string) {
	st := StatusFail
	if c.Severity == spec.SeveritySHOULD {
		st = StatusWarn
	}
	r.Assertions = append(r.Assertions, Assertion{st, c, detail})
}

// Failed reports whether any assertion is StatusFail.
func (r *Report) Failed() bool {
	for _, a := range r.Assertions {
		if a.Status == StatusFail {
			return true
		}
	}
	return false
}

// Write renders the report as aligned columns to w.
func (r *Report) Write(w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, a := range r.Assertions {
		fmt.Fprintf(tw, "%s\t%s %s\t%s",
			a.Status.label(), a.Clause.Spec, a.Clause.Section, a.Clause.Text)
		if a.Detail != "" {
			fmt.Fprintf(tw, "\t(%s)", a.Detail)
		}
		fmt.Fprintln(tw)
	}
	_ = tw.Flush()
}
