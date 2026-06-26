package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// runCapture invokes run() with stdout/stderr captured.
func runCapture(args ...string) (code int, stdout, stderr string) {
	var out, errBuf strings.Builder
	code = run(args, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

func TestRunIDTextExitCodes(t *testing.T) {
	// A compliant ID exits 0.
	if code, _, _ := runCapture("id", "spiffe://example.org/web"); code != 0 {
		t.Errorf("compliant id exit = %d, want 0", code)
	}
	// A non-compliant ID (uppercase trust domain) exits 1.
	if code, out, _ := runCapture("id", "spiffe://Example.org/web"); code != 1 {
		t.Errorf("non-compliant id exit = %d, want 1\n%s", code, out)
	}
}

func TestRunIDJSON(t *testing.T) {
	code, stdout, _ := runCapture("id", "--format=json", "spiffe://Example.org/web")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	var got struct {
		Summary    struct{ Failed int } `json:"summary"`
		Assertions []struct {
			Status string `json:"status"`
		} `json:"assertions"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if got.Summary.Failed == 0 {
		t.Error("expected at least one failure in JSON summary")
	}
	if len(got.Assertions) == 0 {
		t.Error("expected assertions in JSON output")
	}
}

func TestRunIDSARIF(t *testing.T) {
	code, stdout, _ := runCapture("id", "--format=sarif", "spiffe://example.org/web")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (compliant)", code)
	}
	var got struct {
		Version string `json:"version"`
		Runs    []json.RawMessage
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if got.Version != "2.1.0" {
		t.Errorf("sarif version = %q, want 2.1.0", got.Version)
	}
}

func TestRunBadFormat(t *testing.T) {
	code, _, stderr := runCapture("id", "--format=toml", "spiffe://example.org/web")
	if code != 2 {
		t.Errorf("bad format exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "unknown format") {
		t.Errorf("stderr = %q, want it to mention unknown format", stderr)
	}
}
