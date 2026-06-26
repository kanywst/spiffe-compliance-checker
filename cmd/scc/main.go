// Command scc (SPIFFE Compliance Checker) evaluates SPIFFE spec MUST clauses
// against artifacts supplied on the command line. Exit code is 1 if any MUST
// clause is violated, 0 otherwise. SHOULD violations print as WARN and do
// not affect the exit code.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/kanywst/spiffe-compliance-checker/internal/bundle"
	"github.com/kanywst/spiffe-compliance-checker/internal/id"
	"github.com/kanywst/spiffe-compliance-checker/internal/jwtsvid"
	"github.com/kanywst/spiffe-compliance-checker/internal/report"
	"github.com/kanywst/spiffe-compliance-checker/internal/x509svid"
)

// Populated at build time by goreleaser via -ldflags. Defaults are sentinels
// used in `go run` / `go install` builds.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const usage = `scc — SPIFFE Compliance Checker

Usage:
  scc id        [--format text|json|sarif] <spiffe-id-string>
  scc x509-svid [--format text|json|sarif] <cert.pem | cert.der>
  scc jwt-svid  [--format text|json|sarif] <token>
  scc bundle    [--format text|json|sarif] <bundle.json>

Each subcommand prints one line per checked clause. Exit code is 1 if any
MUST clause fails, 0 otherwise. SHOULD violations are reported as WARN and
do not affect the exit code.

--format selects the output: text (default, human-readable), json (a stable
object for automation), or sarif (SARIF 2.1.0 for GitHub Code Scanning). The
exit code is identical across formats, so json/sarif are safe to gate CI on.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]

	switch cmd {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	case "-v", "--version", "version":
		fmt.Fprintf(stdout, "scc %s (commit %s, built %s)\n", version, commit, date)
		return 0
	case "id":
		return runID(rest, stdout, stderr)
	case "x509-svid":
		return runX509(rest, stdout, stderr)
	case "jwt-svid":
		return runJWT(rest, stdout, stderr)
	case "bundle":
		return runBundle(rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "scc: unknown subcommand %q\n\n%s", cmd, usage)
		return 2
	}
}

// addFormatFlag registers the shared --format flag on a subcommand's flag set.
func addFormatFlag(fs *flag.FlagSet) *string {
	return fs.String("format", "text", "output format: text, json, or sarif")
}

// emit renders rep in the requested format and maps the outcome to an exit
// code: 1 if any MUST clause failed, 2 on a usage/render error, 0 otherwise.
func emit(rep *report.Report, format string, stdout, stderr io.Writer) int {
	f, err := report.ParseFormat(format)
	if err != nil {
		fmt.Fprintf(stderr, "scc: %v\n", err)
		return 2
	}
	if err := rep.Render(stdout, f); err != nil {
		fmt.Fprintf(stderr, "scc: render: %v\n", err)
		return 2
	}
	if rep.Failed() {
		return 1
	}
	return 0
}

func runID(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("id", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := addFormatFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "scc id: expected exactly one SPIFFE ID string")
		return 2
	}
	rep := &report.Report{Subject: "scc id  " + fs.Arg(0)}
	id.Check(rep, fs.Arg(0))
	return emit(rep, *format, stdout, stderr)
}

func runX509(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("x509-svid", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := addFormatFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "scc x509-svid: expected exactly one certificate path")
		return 2
	}
	rep := &report.Report{Subject: "scc x509-svid  " + fs.Arg(0), Artifact: fs.Arg(0)}
	if err := x509svid.CheckFile(rep, fs.Arg(0)); err != nil {
		fmt.Fprintf(stderr, "scc x509-svid: %v\n", err)
		return 2
	}
	return emit(rep, *format, stdout, stderr)
}

func runJWT(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("jwt-svid", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := addFormatFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "scc jwt-svid: expected exactly one token")
		return 2
	}
	rep := &report.Report{Subject: "scc jwt-svid  <token>"}
	jwtsvid.Check(rep, fs.Arg(0))
	return emit(rep, *format, stdout, stderr)
}

func runBundle(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("bundle", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := addFormatFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "scc bundle: expected exactly one bundle path")
		return 2
	}
	rep := &report.Report{Subject: "scc bundle  " + fs.Arg(0), Artifact: fs.Arg(0)}
	if err := bundle.CheckFile(rep, fs.Arg(0)); err != nil {
		fmt.Fprintf(stderr, "scc bundle: %v\n", err)
		return 2
	}
	return emit(rep, *format, stdout, stderr)
}
