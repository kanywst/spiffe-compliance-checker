package bundlemap_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kanywst/spiffe-compliance-checker/internal/bundlemap"
	"github.com/kanywst/spiffe-compliance-checker/internal/report"
)

func TestCheck(t *testing.T) {
	cases := []struct {
		name           string
		raw            string
		wantFailed     bool
		wantContainAny []string
	}{
		{
			// Appendix B's example map, minus the x5c blob so the entry is a
			// jwt-svid key rather than an x509-svid one.
			name: "valid map with one trust domain",
			raw: `{
				"trust_domains": {
					"example.com": {
						"spiffe_sequence": 12035488,
						"keys": [
							{"kty": "RSA", "kid": "jwt-1", "use": "jwt-svid", "n": "abc", "e": "AQAB"}
						]
					}
				}
			}`,
			wantFailed:     false,
			wantContainAny: []string{"1 trust domain", `trust_domains["example.com"]`},
		},
		{
			name:           "trust_domains absent",
			raw:            `{"spiffe_sequence": 1}`,
			wantFailed:     true,
			wantContainAny: []string{`"trust_domains" key absent`},
		},
		{
			// §5.1.1: "A static 'trust_domains' key MUST be set, and MAY be
			// empty." An empty map is compliant, not suspicious.
			name:           "empty trust_domains is allowed",
			raw:            `{"trust_domains": {}}`,
			wantFailed:     false,
			wantContainAny: []string{"0 trust domains"},
		},
		{
			name:           "trust_domains is not an object",
			raw:            `{"trust_domains": []}`,
			wantFailed:     true,
			wantContainAny: []string{`"trust_domains" is`, "want object"},
		},
		{
			// §5.1.1 + §6.3: encoding/json keeps only the last of a duplicated
			// key, so this is the case a plain unmarshal cannot catch.
			name: "duplicate trust domain names rejected",
			raw: `{
				"trust_domains": {
					"example.com": {"spiffe_sequence": 1, "keys": []},
					"example.com": {"spiffe_sequence": 2, "keys": []}
				}
			}`,
			wantFailed:     true,
			wantContainAny: []string{"duplicate trust domain name(s): example.com"},
		},
		{
			// §5.1.1 defers to SPIFFE-ID.md §2 for name validity, so an
			// uppercase key is a MUST violation of the ID spec.
			name: "invalid trust domain name",
			raw: `{
				"trust_domains": {
					"Example.COM": {"spiffe_sequence": 1, "keys": []}
				}
			}`,
			wantFailed:     true,
			wantContainAny: []string{"trust domain MUST be lowercase", `trust_domain="Example.COM"`},
		},
		{
			name: "entry is not a bundle object",
			raw: `{
				"trust_domains": {
					"example.com": "not-a-bundle"
				}
			}`,
			wantFailed:     true,
			wantContainAny: []string{"want object"},
		},
		{
			// §5.1.1 inverts the standalone expectation: inside a map the hint
			// is discouraged, so its presence warns rather than its absence.
			name: "refresh hint inside a map warns",
			raw: `{
				"trust_domains": {
					"example.com": {
						"spiffe_sequence": 1,
						"spiffe_refresh_hint": 300,
						"keys": []
					}
				}
			}`,
			wantFailed:     false,
			wantContainAny: []string{"spiffe_refresh_hint present", `SHOULD omit "spiffe_refresh_hint"`},
		},
		{
			name: "omitting the refresh hint inside a map passes",
			raw: `{
				"trust_domains": {
					"example.com": {"spiffe_sequence": 1, "keys": []}
				}
			}`,
			wantFailed:     false,
			wantContainAny: []string{`SHOULD omit "spiffe_refresh_hint"`},
		},
		{
			// The embedded bundle is handed to internal/bundle verbatim, so its
			// clauses must still fire — with the trust domain named in the
			// detail so the reader knows which bundle is at fault.
			name: "embedded bundle failure is attributed to its trust domain",
			raw: `{
				"trust_domains": {
					"example.com": {
						"spiffe_sequence": 1,
						"keys": [
							{"kty": "RSA", "use": "jwt-svid", "n": "abc", "e": "AQAB"}
						]
					}
				}
			}`,
			wantFailed:     true,
			wantContainAny: []string{`trust_domains["example.com"].keys[0]: kid absent`},
		},
		{
			// kid uniqueness is scoped to one bundle (WIT-SVID.md §6.1), so the
			// same kid in two different trust domains is fine.
			name: "same kid in two trust domains is not a collision",
			raw: `{
				"trust_domains": {
					"a.example.com": {
						"spiffe_sequence": 1,
						"keys": [{"kty": "RSA", "kid": "shared", "use": "jwt-svid"}]
					},
					"b.example.com": {
						"spiffe_sequence": 1,
						"keys": [{"kty": "RSA", "kid": "shared", "use": "jwt-svid"}]
					}
				}
			}`,
			wantFailed: false,
		},
		{
			name: "duplicate kid within one bundle still collides",
			raw: `{
				"trust_domains": {
					"example.com": {
						"spiffe_sequence": 1,
						"keys": [
							{"kty": "RSA", "kid": "dup", "use": "jwt-svid"},
							{"kty": "RSA", "kid": "dup", "use": "jwt-svid"}
						]
					}
				}
			}`,
			wantFailed:     true,
			wantContainAny: []string{`trust_domains["example.com"]: duplicate kid(s): dup`},
		},
		{
			// spiffe_sequence must survive past 2^53, which the default
			// float64 decode path silently corrupts.
			name: "large spiffe_sequence keeps full integer width",
			raw: `{
				"trust_domains": {
					"example.com": {"spiffe_sequence": 9007199254740993, "keys": []}
				}
			}`,
			wantFailed:     false,
			wantContainAny: []string{"spiffe_sequence=9007199254740993"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &report.Report{}
			if err := bundlemap.Check(r, []byte(tc.raw)); err != nil {
				t.Fatalf("Check error: %v", err)
			}
			// Render unconditionally: several cases assert on WARN text, which
			// leaves Failed() false, so the substring checks must run for
			// passing cases too.
			var buf strings.Builder
			r.Write(&buf)
			out := buf.String()

			if got := r.Failed(); got != tc.wantFailed {
				t.Fatalf("Failed()=%v, want %v\nreport:\n%s", got, tc.wantFailed, out)
			}
			for _, sub := range tc.wantContainAny {
				if !strings.Contains(out, sub) {
					t.Errorf("expected report to mention %q\nreport:\n%s", sub, out)
				}
			}
		})
	}
}

func TestCheckInvalidJSON(t *testing.T) {
	r := &report.Report{}
	err := bundlemap.Check(r, []byte(`{"trust_domains":`))
	if err == nil {
		t.Fatal("expected an error for malformed JSON")
	}
	if !strings.Contains(err.Error(), "bundle map is not valid JSON") {
		t.Errorf("error = %q, want it to mention an invalid bundle map", err)
	}
}

// Document order, not map order, drives the report so it reads top-to-bottom
// like the file.
func TestCheckReportsTrustDomainsInDocumentOrder(t *testing.T) {
	raw := `{
		"trust_domains": {
			"zebra.example.com": {"spiffe_sequence": 1, "keys": []},
			"alpha.example.com": {"spiffe_sequence": 1, "keys": []}
		}
	}`
	r := &report.Report{}
	if err := bundlemap.Check(r, []byte(raw)); err != nil {
		t.Fatalf("Check error: %v", err)
	}
	var buf strings.Builder
	r.Write(&buf)
	out := buf.String()

	zebra := strings.Index(out, `trust_domains["zebra.example.com"]`)
	alpha := strings.Index(out, `trust_domains["alpha.example.com"]`)
	if zebra < 0 || alpha < 0 {
		t.Fatalf("expected both trust domains in the report:\n%s", out)
	}
	if zebra > alpha {
		t.Errorf("expected zebra before alpha (document order), got zebra=%d alpha=%d\n%s",
			zebra, alpha, out)
	}
}

func TestCheckFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "map.json")
	raw := `{"trust_domains": {"example.com": {"spiffe_sequence": 1, "keys": []}}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &report.Report{}
	if err := bundlemap.CheckFile(r, path); err != nil {
		t.Fatalf("CheckFile error: %v", err)
	}
	if r.Failed() {
		var buf strings.Builder
		r.Write(&buf)
		t.Errorf("expected a compliant map to pass:\n%s", buf.String())
	}

	if err := bundlemap.CheckFile(r, filepath.Join(dir, "missing.json")); err == nil {
		t.Error("expected an error for a missing file")
	}
}
