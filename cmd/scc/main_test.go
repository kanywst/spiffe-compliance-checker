package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
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

// mkWIT builds a compact-serialized token from the given JSON header and
// payload. The signature is not checked, so a placeholder suffices.
func mkWIT(header, payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(header)) + "." + enc([]byte(payload)) + ".sig"
}

func TestRunWITExitCodes(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	compliant := mkWIT(
		`{"alg":"ES256","typ":"wit+jwt","kid":"k1"}`,
		fmt.Sprintf(`{"sub":"spiffe://example.org/web","exp":%d,`+
			`"cnf":{"jwk":{"alg":"ES256","kty":"EC","crv":"P-256","x":"a","y":"b"}}}`, exp),
	)
	if code, out, _ := runCapture("wit-svid", compliant); code != 0 {
		t.Errorf("compliant wit-svid exit = %d, want 0\n%s", code, out)
	}
	// aud is forbidden in a WIT-SVID even though a JWT-SVID requires it.
	withAud := mkWIT(
		`{"alg":"ES256","typ":"wit+jwt","kid":"k1"}`,
		fmt.Sprintf(`{"sub":"spiffe://example.org/web","aud":["reports"],"exp":%d,`+
			`"cnf":{"jwk":{"alg":"ES256","kty":"EC","crv":"P-256","x":"a","y":"b"}}}`, exp),
	)
	if code, out, _ := runCapture("wit-svid", withAud); code != 1 {
		t.Errorf("wit-svid with aud exit = %d, want 1\n%s", code, out)
	}
}

func TestRunWITUsageErrors(t *testing.T) {
	if code, _, stderr := runCapture("wit-svid"); code != 2 {
		t.Errorf("no-arg exit = %d, want 2 (stderr: %q)", code, stderr)
	}
	if code, _, _ := runCapture("wit-svid", "a", "b"); code != 2 {
		t.Errorf("two-arg exit = %d, want 2", code)
	}
}

func TestUsageListsEverySubcommand(t *testing.T) {
	code, stdout, _ := runCapture("--help")
	if code != 0 {
		t.Fatalf("--help exit = %d, want 0", code)
	}
	for _, sub := range []string{"id", "x509-svid", "jwt-svid", "wit-svid", "bundle"} {
		if !strings.Contains(stdout, "scc "+sub) {
			t.Errorf("usage does not mention subcommand %q\n%s", sub, stdout)
		}
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
