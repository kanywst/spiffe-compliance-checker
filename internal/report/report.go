// Package report aggregates PASS/FAIL/WARN outcomes from compliance checks
// and renders them as a colored, emoji-tagged human report. Color is emitted
// only when the output stream is a TTY and NO_COLOR is unset, so the same
// renderer is safe in scripts, CI logs, and test buffers.
package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"charm.land/lipgloss/v2"
	"golang.org/x/term"

	"github.com/kanywst/spiffe-compliance-checker/internal/spec"
)

// Status is the outcome of evaluating one clause against an artifact.
type Status int

const (
	// StatusPass means the artifact satisfies the clause.
	StatusPass Status = iota
	// StatusFail means the artifact violates a MUST / MUST NOT clause.
	StatusFail
	// StatusWarn means the artifact violates a SHOULD / SHOULD NOT clause.
	StatusWarn
)

// Assertion is one evaluated clause.
type Assertion struct {
	Status Status
	Clause spec.Clause
	Detail string // optional offending value or supporting observation
}

// Report collects assertions in evaluation order.
type Report struct {
	Assertions []Assertion
	// Subject is an optional one-line header describing what was checked
	// (e.g. "scc id  spiffe://example.com/foo"). Left empty by callers that
	// only want the assertions printed.
	Subject string
	// Artifact is the optional file path of the scanned input. When set, the
	// SARIF renderer attaches it as each result's location URI so GitHub Code
	// Scanning can map findings back to a file. Left empty for inputs that are
	// not files (a SPIFFE ID string, a JWT token).
	Artifact string
}

// Pass records a satisfied clause.
func (r *Report) Pass(c spec.Clause, detail string) {
	r.Assertions = append(r.Assertions, Assertion{StatusPass, c, detail})
}

// Fail records a violated clause. SHOULD-severity clauses are downgraded to
// warnings so they do not affect the exit code.
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

// Write renders the report to w. Colors and Unicode are emitted only when w
// is a TTY and NO_COLOR is unset.
func (r *Report) Write(w io.Writer) {
	st := stylesFor(w)
	fmt.Fprintln(w)
	if r.Subject != "" {
		fmt.Fprintln(w, st.subject.Render(r.Subject))
		fmt.Fprintln(w)
	}

	// Pre-compute the spec+section column width so citations align even when
	// the longest spec name appears late in the list.
	maxCite := 0
	for _, a := range r.Assertions {
		c := a.Clause.Spec + " " + a.Clause.Section
		if len(c) > maxCite {
			maxCite = len(c)
		}
	}

	for _, a := range r.Assertions {
		icon, label := st.iconLabel(a.Status)
		cite := pad(a.Clause.Spec+" "+a.Clause.Section, maxCite)
		fmt.Fprintf(w, "  %s %s  %s  %s\n",
			icon,
			label,
			st.cite.Render(cite),
			st.clauseText(a.Status, a.Clause.Text),
		)
		if a.Detail != "" {
			fmt.Fprintf(w, "         %s\n", st.detail.Render("→ "+a.Detail))
		}
	}

	pass, fail, warn := r.counts()
	fmt.Fprintln(w)
	fmt.Fprintln(w, st.rule.Render(strings.Repeat("─", maxCite+24)))
	fmt.Fprintln(w, st.summary(pass, fail, warn))
	fmt.Fprintln(w)
}

func (r *Report) counts() (pass, fail, warn int) {
	for _, a := range r.Assertions {
		switch a.Status {
		case StatusPass:
			pass++
		case StatusFail:
			fail++
		case StatusWarn:
			warn++
		}
	}
	return
}

// styles holds the rendering palette. When color is off, every style is a
// no-op so the output is plain text.
type styles struct {
	pass    lipgloss.Style
	fail    lipgloss.Style
	warn    lipgloss.Style
	cite    lipgloss.Style
	clause  lipgloss.Style
	subject lipgloss.Style
	detail  lipgloss.Style
	rule    lipgloss.Style
	color   bool
}

func stylesFor(w io.Writer) *styles {
	on := colorEnabled(w)
	if !on {
		return &styles{}
	}
	return &styles{
		pass:    lipgloss.NewStyle().Foreground(lipgloss.Color("#22c55e")).Bold(true), // green
		fail:    lipgloss.NewStyle().Foreground(lipgloss.Color("#ef4444")).Bold(true), // red
		warn:    lipgloss.NewStyle().Foreground(lipgloss.Color("#f59e0b")).Bold(true), // amber
		cite:    lipgloss.NewStyle().Foreground(lipgloss.Color("#64748b")),            // slate
		clause:  lipgloss.NewStyle(),
		subject: lipgloss.NewStyle().Foreground(lipgloss.Color("#a78bfa")).Bold(true), // violet
		detail:  lipgloss.NewStyle().Foreground(lipgloss.Color("#94a3b8")).Italic(true),
		rule:    lipgloss.NewStyle().Foreground(lipgloss.Color("#334155")),
		color:   true,
	}
}

func (s *styles) iconLabel(st Status) (icon, label string) {
	switch st {
	case StatusPass:
		if s.color {
			return s.pass.Render("✓"), s.pass.Render("PASS")
		}
		return "PASS", "    "
	case StatusFail:
		if s.color {
			return s.fail.Render("✗"), s.fail.Render("FAIL")
		}
		return "FAIL", "    "
	case StatusWarn:
		if s.color {
			return s.warn.Render("⚠"), s.warn.Render("WARN")
		}
		return "WARN", "    "
	}
	return "?", "?"
}

func (s *styles) clauseText(st Status, text string) string {
	if !s.color {
		return text
	}
	if st == StatusFail {
		// Tint failing clause text so the reader's eye jumps to it.
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#fecaca")).Render(text)
	}
	return s.clause.Render(text)
}

func (s *styles) summary(pass, fail, warn int) string {
	bullet := "·"
	if !s.color {
		return fmt.Sprintf("%d passed %s %d failed %s %d warnings",
			pass, bullet, fail, bullet, warn)
	}
	parts := []string{
		s.pass.Render(fmt.Sprintf("%d passed", pass)),
		s.fail.Render(fmt.Sprintf("%d failed", fail)),
		s.warn.Render(fmt.Sprintf("%d warnings", warn)),
	}
	sep := s.rule.Render("  " + bullet + "  ")
	return strings.Join(parts, sep)
}

func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

func colorEnabled(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}
