package bundle_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/0-draft/spiffe-compliance-checker/internal/bundle"
	"github.com/0-draft/spiffe-compliance-checker/internal/report"
)

// chunkBase64 inserts a newline every n characters, mimicking how real-world
// JWKS pretty-printers wrap long x5c values.
func chunkBase64(s string, n int) string {
	var out strings.Builder
	for i := 0; i < len(s); i += n {
		end := i + n
		if end > len(s) {
			end = len(s)
		}
		out.WriteString(s[i:end])
		if end < len(s) {
			out.WriteString("\\n")
		}
	}
	return out.String()
}

// makeCertB64 returns a base64-encoded DER X.509 certificate suitable for
// embedding in a JWKS x5c entry. Tests use it so the bundle checker's
// "x5c MUST contain a parseable cert" assertion has something real to chew on.
func makeCertB64(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		URIs:                  []*url.URL{{Scheme: "spiffe", Host: "example.com"}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func TestCheck(t *testing.T) {
	certB64 := makeCertB64(t)

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
					{"kty": "RSA", "use": "x509-svid", "x5c": ["` + certB64 + `"]},
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
					{"kty": "RSA", "use": "x509-svid", "kid": "nope", "x5c": ["` + certB64 + `"]}
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
			wantContainAny: []string{"kid absent"},
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
					{"kty": "RSA", "use": "x509-svid", "x5c": ["` + certB64 + `", "` + certB64 + `"]}
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
		{
			// Regression: x5c content must be valid base64 + parseable cert.
			name: "x5c not valid base64",
			raw: `{
				"spiffe_sequence": 1,
				"spiffe_refresh_hint": 300,
				"keys": [
					{"kty": "RSA", "use": "x509-svid", "x5c": ["not---base64---!@#$"]}
				]
			}`,
			wantFailed:     true,
			wantContainAny: []string{"not valid base64"},
		},
		{
			// Regression: base64 decodes but isn't a DER X.509 certificate.
			name: "x5c is base64 but not a cert",
			raw: `{
				"spiffe_sequence": 1,
				"spiffe_refresh_hint": 300,
				"keys": [
					{"kty": "RSA", "use": "x509-svid", "x5c": ["aGVsbG8gd29ybGQ="]}
				]
			}`,
			wantFailed:     true,
			wantContainAny: []string{"not a parseable X.509 cert"},
		},
		{
			name: "x5c[0] is not a string",
			raw: `{
				"spiffe_sequence": 1,
				"spiffe_refresh_hint": 300,
				"keys": [
					{"kty": "RSA", "use": "x509-svid", "x5c": [123]}
				]
			}`,
			wantFailed:     true,
			wantContainAny: []string{"want string"},
		},
		{
			// Regression: real-world JWKS line-wrap base64 in x5c.
			name: "x5c with embedded newlines and spaces",
			raw: `{
				"spiffe_sequence": 1,
				"spiffe_refresh_hint": 300,
				"keys": [
					{"kty": "RSA", "use": "x509-svid", "x5c": ["` + chunkBase64(certB64, 32) + `"]}
				]
			}`,
			wantFailed: false,
		},
		{
			// Regression: spec implies non-negative; negative makes no sense.
			name: "negative spiffe_sequence rejected",
			raw: `{
				"spiffe_sequence": -1,
				"spiffe_refresh_hint": 300,
				"keys": [
					{"kty": "RSA", "use": "jwt-svid", "kid": "k1"}
				]
			}`,
			wantFailed:     false, // SHOULD-severity (sequence is SHOULD)
			wantContainAny: []string{"must be non-negative"},
		},
		{
			name: "negative spiffe_refresh_hint rejected",
			raw: `{
				"spiffe_sequence": 1,
				"spiffe_refresh_hint": -300,
				"keys": [
					{"kty": "RSA", "use": "jwt-svid", "kid": "k1"}
				]
			}`,
			wantFailed:     false, // SHOULD-severity (refresh_hint is SHOULD)
			wantContainAny: []string{"must be non-negative"},
		},
		{
			// Regression: kty present but wrong type (a boolean here)
			// should report a type mismatch, not "absent".
			name: "kty is wrong type",
			raw: `{
				"spiffe_sequence": 1,
				"spiffe_refresh_hint": 300,
				"keys": [
					{"kty": true, "use": "jwt-svid", "kid": "k1"}
				]
			}`,
			wantFailed:     true,
			wantContainAny: []string{"kty is bool"},
		},
		{
			name: "use is wrong type",
			raw: `{
				"spiffe_sequence": 1,
				"spiffe_refresh_hint": 300,
				"keys": [
					{"kty": "RSA", "use": 7, "kid": "k1"}
				]
			}`,
			wantFailed: true,
			wantContainAny: []string{
				"use is",
				"want string",
			},
		},
		{
			name: "jwt kid is wrong type",
			raw: `{
				"spiffe_sequence": 1,
				"spiffe_refresh_hint": 300,
				"keys": [
					{"kty": "RSA", "use": "jwt-svid", "kid": 42}
				]
			}`,
			wantFailed: true,
			wantContainAny: []string{
				"kid is",
				"want string",
			},
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
