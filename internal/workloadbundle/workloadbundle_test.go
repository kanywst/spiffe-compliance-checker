package workloadbundle_test

import (
	"strings"
	"testing"

	"github.com/kanywst/spiffe-compliance-checker/internal/report"
	"github.com/kanywst/spiffe-compliance-checker/internal/workloadbundle"
)

func TestCheck(t *testing.T) {
	cases := []struct {
		name           string
		profile        workloadbundle.Profile
		raw            string
		wantFailed     bool
		wantContainAny []string
	}{
		{
			// What SPIRE's FetchWITBundles returns.
			name:    "wit bundle without use",
			profile: workloadbundle.WIT,
			raw:     `{"keys": [{"kty": "EC", "kid": "k1", "crv": "P-256", "x": "a", "y": "b"}]}`,
		},
		{
			name:           "wit key missing kid",
			profile:        workloadbundle.WIT,
			raw:            `{"keys": [{"kty": "EC", "crv": "P-256", "x": "a", "y": "b"}]}`,
			wantFailed:     true,
			wantContainAny: []string{"kid absent"},
		},
		{
			name:           "wit kid not a string",
			profile:        workloadbundle.WIT,
			raw:            `{"keys": [{"kty": "EC", "kid": 7}]}`,
			wantFailed:     true,
			wantContainAny: []string{"kid is json.Number, want string"},
		},
		{
			name:           "wit duplicate kid",
			profile:        workloadbundle.WIT,
			raw:            `{"keys": [{"kty": "EC", "kid": "k1"}, {"kty": "EC", "kid": "k1"}]}`,
			wantFailed:     true,
			wantContainAny: []string{"duplicate kid(s): k1"},
		},
		{
			name:    "jwt bundle without use",
			profile: workloadbundle.JWT,
			raw:     `{"keys": [{"kty": "RSA", "kid": "k1", "n": "abc", "e": "AQAB"}]}`,
		},
		{
			name:    "jwt bundle with jwt-svid use",
			profile: workloadbundle.JWT,
			raw:     `{"keys": [{"kty": "RSA", "kid": "k1", "use": "jwt-svid"}]}`,
		},
		{
			name:           "jwt bundle carrying a wit key",
			profile:        workloadbundle.JWT,
			raw:            `{"keys": [{"kty": "EC", "kid": "k1"}, {"kty": "EC", "kid": "w1", "use": "wit-svid"}]}`,
			wantFailed:     true,
			wantContainAny: []string{`keys[1]: use="wit-svid"`},
		},
		{
			name:           "jwt bundle carrying an x509 key",
			profile:        workloadbundle.JWT,
			raw:            `{"keys": [{"kty": "EC", "use": "x509-svid", "x5c": ["a"]}]}`,
			wantFailed:     true,
			wantContainAny: []string{`keys[0]: use="x509-svid"`},
		},
		{
			name:    "jwt bundle with sig use",
			profile: workloadbundle.JWT,
			raw:     `{"keys": [{"kty": "RSA", "kid": "k1", "use": "sig"}]}`,
		},
		{
			name:           "jwt bundle with an unknown use",
			profile:        workloadbundle.JWT,
			raw:            `{"keys": [{"kty": "RSA", "kid": "k1", "use": "jwt_svid"}]}`,
			wantFailed:     true,
			wantContainAny: []string{`keys[0]: use="jwt_svid"`},
		},
		{
			name:           "jwt bundle with an empty use",
			profile:        workloadbundle.JWT,
			raw:            `{"keys": [{"kty": "RSA", "kid": "k1", "use": ""}]}`,
			wantFailed:     true,
			wantContainAny: []string{`keys[0]: use=""`},
		},
		{
			name:           "jwt bundle carrying an encryption key",
			profile:        workloadbundle.JWT,
			raw:            `{"keys": [{"kty": "RSA", "kid": "k1", "use": "enc"}]}`,
			wantFailed:     true,
			wantContainAny: []string{`keys[0]: use="enc"`},
		},
		{
			name:           "index kept after a non-object entry",
			profile:        workloadbundle.JWT,
			raw:            `{"keys": [1, {"kty": "EC", "use": "wit-svid"}]}`,
			wantFailed:     true,
			wantContainAny: []string{"keys[0] is not an object", `keys[1]: use="wit-svid"`},
		},
		{
			name:           "kty not a string",
			profile:        workloadbundle.JWT,
			raw:            `{"keys": [{"kty": 5}]}`,
			wantFailed:     true,
			wantContainAny: []string{"kty is json.Number, want string"},
		},
		{
			name:           "keys missing",
			profile:        workloadbundle.JWT,
			raw:            `{}`,
			wantFailed:     true,
			wantContainAny: []string{`"keys" absent`},
		},
		{
			name:           "key without kty",
			profile:        workloadbundle.WIT,
			raw:            `{"keys": [{"kid": "k1"}]}`,
			wantFailed:     true,
			wantContainAny: []string{"kty absent"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &report.Report{}
			if err := workloadbundle.Check(r, tc.profile, []byte(tc.raw)); err != nil {
				t.Fatalf("Check error: %v", err)
			}
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

func TestCheckUnknownProfile(t *testing.T) {
	if err := workloadbundle.Check(&report.Report{}, "x509", []byte(`{"keys": []}`)); err == nil {
		t.Fatal("Check accepted profile x509, want error")
	}
}
