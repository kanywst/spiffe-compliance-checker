package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	for _, sub := range []string{"id", "x509-svid", "jwt-svid", "wit-svid", "bundle", "bundle-map", "federation"} {
		if !strings.Contains(stdout, "scc "+sub) {
			t.Errorf("usage does not mention subcommand %q\n%s", sub, stdout)
		}
	}
}

// writeTemp writes content to a temp file and returns its path.
func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunBundleMapExitCodes(t *testing.T) {
	compliant := writeTemp(t, "map.json", `{
		"trust_domains": {
			"example.com": {
				"spiffe_sequence": 1,
				"keys": [{"kty": "RSA", "kid": "k1", "use": "jwt-svid"}]
			}
		}
	}`)
	if code, out, _ := runCapture("bundle-map", compliant); code != 0 {
		t.Errorf("compliant bundle-map exit = %d, want 0\n%s", code, out)
	}

	// An uppercase trust domain name violates SPIFFE-ID.md §2.1, which
	// §5.1.1 adopts for map keys.
	bad := writeTemp(t, "map.json", `{
		"trust_domains": {"Example.com": {"spiffe_sequence": 1, "keys": []}}
	}`)
	if code, out, _ := runCapture("bundle-map", bad); code != 1 {
		t.Errorf("non-compliant bundle-map exit = %d, want 1\n%s", code, out)
	}
}

func TestRunBundleMapUsageErrors(t *testing.T) {
	if code, _, stderr := runCapture("bundle-map"); code != 2 {
		t.Errorf("no-arg exit = %d, want 2 (stderr: %q)", code, stderr)
	}
	if code, _, stderr := runCapture("bundle-map", "a", "b"); code != 2 {
		t.Errorf("two-arg exit = %d, want 2 (stderr: %q)", code, stderr)
	}
	// A malformed map is a tool-level error (exit 2), not a compliance failure.
	broken := writeTemp(t, "map.json", `{"trust_domains":`)
	if code, _, stderr := runCapture("bundle-map", broken); code != 2 {
		t.Errorf("malformed map exit = %d, want 2 (stderr: %q)", code, stderr)
	}
}

func TestRunFederationExitCodes(t *testing.T) {
	if code, out, _ := runCapture("federation",
		"--url=https://example.com/bundle.json",
		"--profile=https_web",
		"--trust-domain=example.com"); code != 0 {
		t.Errorf("compliant federation exit = %d, want 0\n%s", code, out)
	}

	// §5.2.1.1: a plain http endpoint URL is a MUST violation.
	if code, out, _ := runCapture("federation",
		"--url=http://example.com/bundle.json",
		"--profile=https_web",
		"--trust-domain=example.com"); code != 1 {
		t.Errorf("http endpoint exit = %d, want 1\n%s", code, out)
	}

	// Missing parameters are §5.1 failures, reported rather than rejected, so
	// they exit 1 like any other compliance failure — not 2.
	code, out, _ := runCapture("federation")
	if code != 1 {
		t.Errorf("empty configuration exit = %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "endpoint URL not set") {
		t.Errorf("empty configuration did not report the missing URL\n%s", out)
	}
}

func TestRunFederationUsageErrors(t *testing.T) {
	// The artifact is the flag set, so a positional argument is a usage error.
	if code, _, stderr := runCapture("federation", "https://example.com/bundle.json"); code != 2 {
		t.Errorf("positional-arg exit = %d, want 2 (stderr: %q)", code, stderr)
	}
	// An unreadable bootstrap bundle is a tool-level error, not a compliance
	// failure.
	code, _, stderr := runCapture("federation",
		"--url=https://example.com/bundle.json",
		"--profile=https_spiffe",
		"--trust-domain=example.com",
		"--endpoint-spiffe-id=spiffe://example.com/server",
		"--endpoint-bundle="+filepath.Join(t.TempDir(), "missing.json"))
	if code != 2 {
		t.Errorf("missing bundle exit = %d, want 2 (stderr: %q)", code, stderr)
	}
}

// TestRunFederationSARIFHasNoLocation pins the consequence of a federation
// report carrying no Artifact: the configuration is not a file, so its SARIF
// results must not claim a physical location.
func TestRunFederationSARIFHasNoLocation(t *testing.T) {
	code, stdout, _ := runCapture("federation", "--format=sarif",
		"--url=http://example.com/bundle.json",
		"--profile=https_web",
		"--trust-domain=example.com")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	var got struct {
		Runs []struct {
			Results []struct {
				Locations []json.RawMessage `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if len(got.Runs) == 0 || len(got.Runs[0].Results) == 0 {
		t.Fatalf("expected SARIF results\n%s", stdout)
	}
	for i, res := range got.Runs[0].Results {
		if len(res.Locations) != 0 {
			t.Errorf("result %d carries a location, want none\n%s", i, stdout)
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
