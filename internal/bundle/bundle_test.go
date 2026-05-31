package bundle_test

import (
	"strings"
	"testing"

	"github.com/0-draft/spiffe-compliance-checker/internal/bundle"
	"github.com/0-draft/spiffe-compliance-checker/internal/report"
)

func TestCheck(t *testing.T) {
	cases := []struct {
		name           string
		raw            string
		wantFailed     bool
		wantContainAny []string
	}{
		{
			name: "valid bundle with one x509 and one jwt entry",
			raw: `{
				"spiffe_sequence": 1,
				"spiffe_refresh_hint": 300,
				"keys": [
					{"kty": "RSA", "use": "x509-svid", "x5c": ["MIIBdjCCARug"]},
					{"kty": "RSA", "use": "jwt-svid", "kid": "k1", "n": "abc", "e": "AQAB"}
				]
			}`,
			wantFailed: false,
		},
		{
			name: "keys missing",
			raw: `{
				"spiffe_sequence": 1,
				"spiffe_refresh_hint": 300
			}`,
			wantFailed:     true,
			wantContainAny: []string{`"keys" key absent`},
		},
		{
			name: "x509 entry with kid (forbidden)",
			raw: `{
				"spiffe_sequence": 1,
				"spiffe_refresh_hint": 300,
				"keys": [
					{"kty": "RSA", "use": "x509-svid", "kid": "nope", "x5c": ["MIIB..."]}
				]
			}`,
			wantFailed:     true,
			wantContainAny: []string{"kid present"},
		},
		{
			name: "jwt entry missing kid",
			raw: `{
				"spiffe_sequence": 1,
				"spiffe_refresh_hint": 300,
				"keys": [
					{"kty": "RSA", "use": "jwt-svid", "n": "abc", "e": "AQAB"}
				]
			}`,
			wantFailed:     true,
			wantContainAny: []string{"kid absent or empty"},
		},
		{
			name: "unknown use value",
			raw: `{
				"spiffe_sequence": 1,
				"spiffe_refresh_hint": 300,
				"keys": [
					{"kty": "RSA", "use": "tls"}
				]
			}`,
			wantFailed:     true,
			wantContainAny: []string{"use=tls"},
		},
		{
			name: "missing kty",
			raw: `{
				"spiffe_sequence": 1,
				"spiffe_refresh_hint": 300,
				"keys": [
					{"use": "jwt-svid", "kid": "k1"}
				]
			}`,
			wantFailed:     true,
			wantContainAny: []string{"kty absent"},
		},
		{
			name: "x5c with two certs (forbidden)",
			raw: `{
				"spiffe_sequence": 1,
				"spiffe_refresh_hint": 300,
				"keys": [
					{"kty": "RSA", "use": "x509-svid", "x5c": ["A", "B"]}
				]
			}`,
			wantFailed:     true,
			wantContainAny: []string{"x5c has 2 entries"},
		},
		{
			name: "missing sequence and refresh hint",
			raw: `{
				"keys": [
					{"kty": "RSA", "use": "jwt-svid", "kid": "k1"}
				]
			}`,
			wantFailed: false, // SHOULD violations are WARN, not FAIL
		},
		{
			// Regression: spec allows sequence numbers up to 64-bit width.
			// float64 would silently truncate 9007199254740993 to ...992.
			name: "spiffe_sequence beyond float64 precision",
			raw: `{
				"spiffe_sequence": 9007199254740993,
				"spiffe_refresh_hint": 300,
				"keys": [
					{"kty": "RSA", "use": "jwt-svid", "kid": "k1"}
				]
			}`,
			wantFailed:     false,
			wantContainAny: []string{"spiffe_sequence=9007199254740993"},
		},
		{
			name: "fractional sequence rejected",
			raw: `{
				"spiffe_sequence": 1.5,
				"spiffe_refresh_hint": 300,
				"keys": [
					{"kty": "RSA", "use": "jwt-svid", "kid": "k1"}
				]
			}`,
			wantFailed:     false, // SHOULD-severity downgrade
			wantContainAny: []string{"is not integer"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &report.Report{}
			if err := bundle.Check(r, []byte(tc.raw)); err != nil {
				t.Fatalf("Check error: %v", err)
			}
			if got := r.Failed(); got != tc.wantFailed {
				var buf strings.Builder
				r.Write(&buf)
				t.Fatalf("Failed()=%v, want %v\nreport:\n%s", got, tc.wantFailed, buf.String())
			}
			if !tc.wantFailed {
				return
			}
			var buf strings.Builder
			r.Write(&buf)
			out := buf.String()
			for _, sub := range tc.wantContainAny {
				if !strings.Contains(out, sub) {
					t.Errorf("expected report to mention %q\nreport:\n%s", sub, out)
				}
			}
		})
	}
}
