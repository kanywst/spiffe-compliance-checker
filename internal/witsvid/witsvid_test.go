package witsvid_test

import (
	"encoding/base64"
	"encoding/json"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/spiffe-compliance-checker/internal/report"
	"github.com/kanywst/spiffe-compliance-checker/internal/witsvid"
)

// specAppendixA is the example WIT-SVID published in WIT-SVID.md Appendix A.
// Its exp is fixed in the past, so it is used to pin the structural clauses
// rather than the freshness ones.
const specAppendixA = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImxRU2kzaFpGbmRhMkQtWEprajF6bDdmb0pvdWl3STRuckF5aHk0alppSmciLCJ0eXAiOiJ3aXQrand0In0." +
	"eyJjbmYiOnsiandrIjp7ImFsZyI6IkVTMjU2IiwiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJyelA3bUxDS0FIV21zTTZYMEV3VklTQ19oSTN1amN1OTVmZlVreWVER0dvIiwieSI6InVPcmZEbGp0WDltM2pZLWhzeWhMSllheHRHa3pEdjVlNWttQ2U1OFo5N2cifX0sImV4cCI6MTc2NTQ1NjUwMywiaWF0IjoxNzY1NDUyOTAzLCJqdGkiOiIxeWoxOVY0TWNPQXpNY0ZpN3F2c2dfQWdDeGxyWTVFX3g1MDl3bEtLUXRjIiwic3ViIjoic3BpZmZlOi8vZXhhbXBsZS5jb20vbXktd29ya2xvYWQifQ." +
	"sfhEvZNdY_kWrICF08lX0u__rn39YnTavnW-VPBS20zgowDh6-X43v5eOUKZbjZf06yLBQM-Mry5w1g1QFsCkg"

func mkToken(t *testing.T, header, payload map[string]any) string {
	t.Helper()
	enc := func(m map[string]any) string {
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(header) + "." + enc(payload) + ".sig"
}

// validHeader / validPayload are the minimal spec-compliant token; each case
// below mutates a copy of one of them so the failure under test is the only
// difference from a clean run.
func validHeader() map[string]any {
	return map[string]any{"alg": "ES256", "typ": "wit+jwt", "kid": "k1"}
}

func validPayload(exp int64) map[string]any {
	return map[string]any{
		"sub": "spiffe://example.com/my-workload",
		"exp": exp,
		"cnf": map[string]any{"jwk": map[string]any{
			"alg": "ES256", "crv": "P-256", "kty": "EC", "x": "abc", "y": "def",
		}},
	}
}

func TestCheck(t *testing.T) {
	future := time.Now().Add(time.Hour).Unix()
	past := time.Now().Add(-time.Hour).Unix()

	// mutate applies f to a copy of m so cases stay independent.
	mutate := func(m map[string]any, f func(map[string]any)) map[string]any {
		out := make(map[string]any, len(m))
		maps.Copy(out, m)
		f(out)
		return out
	}

	cases := []struct {
		name           string
		header         map[string]any
		payload        map[string]any
		raw            string // overrides header/payload when non-empty
		wantFailed     bool
		wantContainAny []string
	}{
		{
			name:    "valid token",
			header:  validHeader(),
			payload: validPayload(future),
		},
		{
			// §3.5: nbf is optional, and a past nbf is exactly what the spec
			// recommends to absorb clock skew.
			name:    "valid token with optional jti, iat and past nbf",
			header:  validHeader(),
			payload: mutate(validPayload(future), func(m map[string]any) { m["jti"] = "abc"; m["iat"] = past; m["nbf"] = past }),
		},
		{
			name:           "kid absent",
			header:         mutate(validHeader(), func(m map[string]any) { delete(m, "kid") }),
			payload:        validPayload(future),
			wantFailed:     true,
			wantContainAny: []string{"kid header MUST be present", "kid header absent"},
		},
		{
			name:           "kid empty",
			header:         mutate(validHeader(), func(m map[string]any) { m["kid"] = "" }),
			payload:        validPayload(future),
			wantFailed:     true,
			wantContainAny: []string{"kid is empty"},
		},
		{
			name:           "typ absent",
			header:         mutate(validHeader(), func(m map[string]any) { delete(m, "typ") }),
			payload:        validPayload(future),
			wantFailed:     true,
			wantContainAny: []string{"typ header absent"},
		},
		{
			// A JWT-SVID-shaped typ must not be accepted: the whole point of
			// §2.2 is that the two token types stay distinguishable.
			name:           "typ is JWT not wit+jwt",
			header:         mutate(validHeader(), func(m map[string]any) { m["typ"] = "JWT" }),
			payload:        validPayload(future),
			wantFailed:     true,
			wantContainAny: []string{`typ="JWT"`},
		},
		{
			name:           "alg absent",
			header:         mutate(validHeader(), func(m map[string]any) { delete(m, "alg") }),
			payload:        validPayload(future),
			wantFailed:     true,
			wantContainAny: []string{"alg header absent"},
		},
		{
			name:           "alg none",
			header:         mutate(validHeader(), func(m map[string]any) { m["alg"] = "none" }),
			payload:        validPayload(future),
			wantFailed:     true,
			wantContainAny: []string{`alg="none"`},
		},
		{
			name:           "alg EdDSA is not in the WIT-SVID table",
			header:         mutate(validHeader(), func(m map[string]any) { m["alg"] = "EdDSA" }),
			payload:        validPayload(future),
			wantFailed:     true,
			wantContainAny: []string{`alg="EdDSA"`},
		},
		{
			// §2.4 is SHOULD NOT, so an extra header warns rather than fails —
			// the inverse of the JWT-SVID's closed set.
			name:           "additional header parameter warns but does not fail",
			header:         mutate(validHeader(), func(m map[string]any) { m["jku"] = "https://evil.example/keys" }),
			payload:        validPayload(future),
			wantFailed:     false,
			wantContainAny: []string{"additional header(s): jku"},
		},
		{
			name:           "sub absent",
			header:         validHeader(),
			payload:        mutate(validPayload(future), func(m map[string]any) { delete(m, "sub") }),
			wantFailed:     true,
			wantContainAny: []string{"sub claim absent"},
		},
		{
			name:           "sub is not a SPIFFE ID",
			header:         validHeader(),
			payload:        mutate(validPayload(future), func(m map[string]any) { m["sub"] = "https://example.com/workload" }),
			wantFailed:     true,
			wantContainAny: []string{`scheme MUST be "spiffe"`},
		},
		{
			name:           "cnf absent",
			header:         validHeader(),
			payload:        mutate(validPayload(future), func(m map[string]any) { delete(m, "cnf") }),
			wantFailed:     true,
			wantContainAny: []string{"cnf claim MUST be present", "cnf claim absent"},
		},
		{
			name:           "cnf is not an object",
			header:         validHeader(),
			payload:        mutate(validPayload(future), func(m map[string]any) { m["cnf"] = "k1" }),
			wantFailed:     true,
			wantContainAny: []string{"cnf is string", "want object"},
		},
		{
			name:           "cnf without jwk",
			header:         validHeader(),
			payload:        mutate(validPayload(future), func(m map[string]any) { m["cnf"] = map[string]any{"kid": "k1"} }),
			wantFailed:     true,
			wantContainAny: []string{"cnf.jwk absent"},
		},
		{
			name:   "cnf.jwk.alg absent",
			header: validHeader(),
			payload: mutate(validPayload(future), func(m map[string]any) {
				m["cnf"] = map[string]any{"jwk": map[string]any{"kty": "EC", "crv": "P-256", "x": "a", "y": "b"}}
			}),
			wantFailed:     true,
			wantContainAny: []string{"cnf.jwk.alg absent"},
		},
		{
			name:   "cnf.jwk.alg not in the permitted table",
			header: validHeader(),
			payload: mutate(validPayload(future), func(m map[string]any) {
				m["cnf"] = map[string]any{"jwk": map[string]any{"alg": "HS256", "kty": "oct"}}
			}),
			wantFailed:     true,
			wantContainAny: []string{`cnf.jwk.alg="HS256"`},
		},
		{
			// RFC 7800 defines cnf.jwk as the public key; an EC private
			// scalar in "d" would be handed to every validator that sees it.
			name:   "cnf.jwk leaks the EC private scalar",
			header: validHeader(),
			payload: mutate(validPayload(future), func(m map[string]any) {
				m["cnf"] = map[string]any{"jwk": map[string]any{
					"alg": "ES256", "kty": "EC", "crv": "P-256", "x": "a", "y": "b", "d": "secret",
				}}
			}),
			wantFailed:     true,
			wantContainAny: []string{"private key parameter(s): d"},
		},
		{
			name:   "cnf.jwk leaks RSA private factors",
			header: validHeader(),
			payload: mutate(validPayload(future), func(m map[string]any) {
				m["cnf"] = map[string]any{"jwk": map[string]any{
					"alg": "RS256", "kty": "RSA", "n": "a", "e": "AQAB", "q": "s", "p": "s",
				}}
			}),
			wantFailed:     true,
			wantContainAny: []string{"private key parameter(s): p, q"},
		},
		{
			name:           "exp absent",
			header:         validHeader(),
			payload:        mutate(validPayload(future), func(m map[string]any) { delete(m, "exp") }),
			wantFailed:     true,
			wantContainAny: []string{"exp claim absent"},
		},
		{
			name:           "exp in the past",
			header:         validHeader(),
			payload:        validPayload(past),
			wantFailed:     true,
			wantContainAny: []string{"exp MUST NOT be in the past"},
		},
		{
			name:           "exp is not numeric",
			header:         validHeader(),
			payload:        mutate(validPayload(future), func(m map[string]any) { m["exp"] = "soon" }),
			wantFailed:     true,
			wantContainAny: []string{"exp must be numeric"},
		},
		{
			name:           "nbf in the future",
			header:         validHeader(),
			payload:        mutate(validPayload(future), func(m map[string]any) { m["nbf"] = future }),
			wantFailed:     true,
			wantContainAny: []string{"when nbf is present it MUST NOT be in the future", "(future)"},
		},
		{
			// §3.8: the JWT-SVID requires aud; the WIT-SVID forbids it.
			name:           "aud present",
			header:         validHeader(),
			payload:        mutate(validPayload(future), func(m map[string]any) { m["aud"] = []any{"reports"} }),
			wantFailed:     true,
			wantContainAny: []string{"aud claim MUST NOT be included"},
		},
		{
			// §3.7: an https issuer could be resolved via OIDC Discovery,
			// letting a relying party skip proof of possession. SHOULD -> WARN.
			name:           "iss looks OIDC discoverable",
			header:         validHeader(),
			payload:        mutate(validPayload(future), func(m map[string]any) { m["iss"] = "https://issuer.example.com" }),
			wantFailed:     false,
			wantContainAny: []string{"OpenID Connect Discovery", "without proof of possession"},
		},
		{
			name:    "iss as a SPIFFE ID is fine",
			header:  validHeader(),
			payload: mutate(validPayload(future), func(m map[string]any) { m["iss"] = "spiffe://example.com" }),
		},
		{
			name:           "JWS JSON Serialization rejected",
			raw:            `{"protected":"...","payload":"...","signature":"..."}`,
			wantFailed:     true,
			wantContainAny: []string{"JWS Compact Serialization"},
		},
		{
			name:           "header is not decodable",
			raw:            "!!!.eyJhIjoxfQ.sig",
			wantFailed:     true,
			wantContainAny: []string{"header decode"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok := tc.raw
			if tok == "" {
				tok = mkToken(t, tc.header, tc.payload)
			}
			r := &report.Report{}
			witsvid.Check(r, tok)

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

// TestSpecAppendixA pins the checker against the verbatim example token from
// WIT-SVID.md Appendix A. Every structural clause must pass; only exp, which
// the spec froze in December 2025, is expected to fail.
func TestSpecAppendixA(t *testing.T) {
	r := &report.Report{}
	witsvid.Check(r, specAppendixA)

	var buf strings.Builder
	r.Write(&buf)
	out := buf.String()

	for _, want := range []string{
		"typ=wit+jwt",
		"alg=ES256",
		"kid=lQSi3hZFnda2D-XJkj1zl7foJouiwI4nrAyhy4jZiJg",
		"sub=spiffe://example.com/my-workload",
		"cnf.jwk.alg=ES256",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected report to mention %q\nreport:\n%s", want, out)
		}
	}

	// The only permitted failure is the frozen exp.
	for line := range strings.SplitSeq(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "FAIL") &&
			!strings.Contains(line, "exp MUST NOT be in the past") {
			t.Errorf("unexpected failure against the spec's own example: %s\nreport:\n%s", line, out)
		}
	}
}
