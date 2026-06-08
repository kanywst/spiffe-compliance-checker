package jwtsvid_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/spiffe-compliance-checker/internal/jwtsvid"
	"github.com/kanywst/spiffe-compliance-checker/internal/report"
)

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

func TestCheck(t *testing.T) {
	future := time.Now().Add(time.Hour).Unix()
	past := time.Now().Add(-time.Hour).Unix()

	cases := []struct {
		name           string
		header         map[string]any
		payload        map[string]any
		raw            string // overrides header/payload if non-empty
		wantFailed     bool
		wantContainAny []string
	}{
		{
			name:    "valid token",
			header:  map[string]any{"alg": "RS256", "typ": "JWT", "kid": "k1"},
			payload: map[string]any{"sub": "spiffe://example.com/web", "aud": []string{"reports"}, "exp": future},
		},
		{
			name:           "alg none",
			header:         map[string]any{"alg": "none"},
			payload:        map[string]any{"sub": "spiffe://example.com/a", "aud": []string{"x"}, "exp": future},
			wantFailed:     true,
			wantContainAny: []string{"alg MUST be one of"},
		},
		{
			name:           "alg HS256",
			header:         map[string]any{"alg": "HS256"},
			payload:        map[string]any{"sub": "spiffe://example.com/a", "aud": []string{"x"}, "exp": future},
			wantFailed:     true,
			wantContainAny: []string{"alg MUST be one of"},
		},
		{
			name:           "missing sub",
			header:         map[string]any{"alg": "ES256"},
			payload:        map[string]any{"aud": []string{"x"}, "exp": future},
			wantFailed:     true,
			wantContainAny: []string{"sub claim MUST be set"},
		},
		{
			name:           "missing aud",
			header:         map[string]any{"alg": "ES256"},
			payload:        map[string]any{"sub": "spiffe://example.com/a", "exp": future},
			wantFailed:     true,
			wantContainAny: []string{"aud claim MUST be present"},
		},
		{
			name:           "missing exp",
			header:         map[string]any{"alg": "ES256"},
			payload:        map[string]any{"sub": "spiffe://example.com/a", "aud": []string{"x"}},
			wantFailed:     true,
			wantContainAny: []string{"exp claim MUST be set"},
		},
		{
			name:           "expired token",
			header:         map[string]any{"alg": "ES256"},
			payload:        map[string]any{"sub": "spiffe://example.com/a", "aud": []string{"x"}, "exp": past},
			wantFailed:     true,
			wantContainAny: []string{"exp MUST NOT be in the past"},
		},
		{
			name:           "JSON serialization not Compact",
			raw:            `{"protected":"...","payload":"...","signature":"..."}`,
			wantFailed:     true,
			wantContainAny: []string{"JWS Compact Serialization"},
		},
		{
			name:           "bad typ",
			header:         map[string]any{"alg": "RS256", "typ": "foo"},
			payload:        map[string]any{"sub": "spiffe://example.com/a", "aud": []string{"x"}, "exp": future},
			wantFailed:     true,
			wantContainAny: []string{`typ header is set, value MUST be`},
		},
		{
			name:           "sub not a SPIFFE ID",
			header:         map[string]any{"alg": "RS256"},
			payload:        map[string]any{"sub": "alice@example.com", "aud": []string{"x"}, "exp": future},
			wantFailed:     true,
			wantContainAny: []string{`scheme MUST be "spiffe"`},
		},
		{
			// Regression: aud as a number should be rejected as malformed,
			// not silently treated as absent.
			name:           "aud is a number",
			header:         map[string]any{"alg": "RS256"},
			payload:        map[string]any{"sub": "spiffe://example.com/a", "aud": 42, "exp": future},
			wantFailed:     true,
			wantContainAny: []string{"must be a string or an array"},
		},
		{
			// Regression: aud as a mixed-type array (string + number) is
			// invalid per RFC 7519.
			name:           "aud array with non-string element",
			header:         map[string]any{"alg": "RS256"},
			payload:        map[string]any{"sub": "spiffe://example.com/a", "aud": []any{"ok", 7}, "exp": future},
			wantFailed:     true,
			wantContainAny: []string{"must be a string or an array"},
		},
		{
			// Regression: typ present but not a string — must not silently
			// coerce to "" and report `typ=""`.
			name:           "typ is a number",
			header:         map[string]any{"alg": "RS256", "typ": 42},
			payload:        map[string]any{"sub": "spiffe://example.com/a", "aud": []string{"x"}, "exp": future},
			wantFailed:     true,
			wantContainAny: []string{"typ is"},
		},
		{
			// Regression: sub present but not a string — must report type
			// mismatch, not "absent".
			name:           "sub is a boolean",
			header:         map[string]any{"alg": "RS256"},
			payload:        map[string]any{"sub": true, "aud": []string{"x"}, "exp": future},
			wantFailed:     true,
			wantContainAny: []string{"sub claim is"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok := tc.raw
			if tok == "" {
				tok = mkToken(t, tc.header, tc.payload)
			}
			r := &report.Report{}
			jwtsvid.Check(r, tok)
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
