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

	"github.com/0-draft/spiffe-compliance-checker/internal/bundle"
	"github.com/0-draft/spiffe-compliance-checker/internal/id"
	"github.com/0-draft/spiffe-compliance-checker/internal/jwtsvid"
	"github.com/0-draft/spiffe-compliance-checker/internal/report"
	"github.com/0-draft/spiffe-compliance-checker/internal/x509svid"
)

const usage = `scc — SPIFFE Compliance Checker

Usage:
  scc id        <spiffe-id-string>
  scc x509-svid <cert.pem | cert.der>
  scc jwt-svid  <token>
  scc bundle    <bundle.json>

Each subcommand prints one line per checked clause. Exit code is 1 if any
MUST clause fails, 0 otherwise. SHOULD violations are reported as WARN and
do not affect the exit code.
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

func runID(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("id", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "scc id: expected exactly one SPIFFE ID string")
		return 2
	}
	rep := &report.Report{Subject: "scc id  " + fs.Arg(0)}
	id.Check(rep, fs.Arg(0))
	rep.Write(stdout)
	if rep.Failed() {
		return 1
	}
	return 0
}

func runX509(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("x509-svid", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "scc x509-svid: expected exactly one certificate path")
		return 2
	}
	rep := &report.Report{Subject: "scc x509-svid  " + fs.Arg(0)}
	if err := x509svid.CheckFile(rep, fs.Arg(0)); err != nil {
		fmt.Fprintf(stderr, "scc x509-svid: %v\n", err)
		return 2
	}
	rep.Write(stdout)
	if rep.Failed() {
		return 1
	}
	return 0
}

func runJWT(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("jwt-svid", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "scc jwt-svid: expected exactly one token")
		return 2
	}
	rep := &report.Report{Subject: "scc jwt-svid  <token>"}
	jwtsvid.Check(rep, fs.Arg(0))
	rep.Write(stdout)
	if rep.Failed() {
		return 1
	}
	return 0
}

func runBundle(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("bundle", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "scc bundle: expected exactly one bundle path")
		return 2
	}
	rep := &report.Report{Subject: "scc bundle  " + fs.Arg(0)}
	if err := bundle.CheckFile(rep, fs.Arg(0)); err != nil {
		fmt.Fprintf(stderr, "scc bundle: %v\n", err)
		return 2
	}
	rep.Write(stdout)
	if rep.Failed() {
		return 1
	}
	return 0
}
