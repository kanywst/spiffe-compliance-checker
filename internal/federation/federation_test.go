package federation_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kanywst/spiffe-compliance-checker/internal/federation"
	"github.com/kanywst/spiffe-compliance-checker/internal/report"
)

func TestCheck(t *testing.T) {
	cases := []struct {
		name           string
		cfg            federation.Config
		wantFailed     bool
		wantContainAny []string
	}{
		{
			// Figure 1: the minimal https_web configuration the spec prints.
			name: "valid https_web configuration",
			cfg: federation.Config{
				URL:         "https://example.com/production/bundle.json",
				Profile:     federation.ProfileWeb,
				TrustDomain: "prod.example.com",
			},
			wantFailed:     false,
			wantContainAny: []string{"https_web", "prod.example.com"},
		},
		{
			// Figure 4: a non-self-serving https_spiffe configuration. The
			// endpoint's trust domain differs from the one being fetched, so
			// no bootstrap bundle belongs here.
			name: "valid non-self-serving https_spiffe configuration",
			cfg: federation.Config{
				URL:         "https://example.com/production/bundle.json",
				Profile:     federation.ProfileSPIFFE,
				TrustDomain: "prod.example.com",
				EndpointID:  "spiffe://example.com/spiffe-bundle-server",
			},
			wantFailed: false,
		},
		{
			name:       "empty configuration fails all three §5.1 parameters",
			cfg:        federation.Config{},
			wantFailed: true,
			wantContainAny: []string{
				"endpoint URL not set",
				"endpoint profile not set",
				"trust domain not set",
			},
		},
		{
			// §5.2.1.1 / §5.2.2.1: http is not a bundle endpoint URL.
			name: "http scheme rejected",
			cfg: federation.Config{
				URL:         "http://example.com/bundle.json",
				Profile:     federation.ProfileWeb,
				TrustDomain: "example.com",
			},
			wantFailed:     true,
			wantContainAny: []string{`scheme="http"`},
		},
		{
			name: "userinfo in the authority rejected",
			cfg: federation.Config{
				URL:         "https://user:pass@example.com/bundle.json",
				Profile:     federation.ProfileWeb,
				TrustDomain: "example.com",
			},
			wantFailed:     true,
			wantContainAny: []string{"userinfo present in authority"},
		},
		{
			// RFC 3986 makes the scheme case-insensitive, so HTTPS is the same
			// scheme as https and must not be reported as a violation.
			name: "uppercase scheme accepted",
			cfg: federation.Config{
				URL:         "HTTPS://example.com/bundle.json",
				Profile:     federation.ProfileWeb,
				TrustDomain: "example.com",
			},
			wantFailed: false,
		},
		{
			// A URL that will not parse leaves the §5.2.x.1 clauses no input,
			// so the checker reports the parse error against the scheme clause
			// and moves on rather than asserting twice about nothing.
			name: "unparseable URL reported once",
			cfg: federation.Config{
				URL:         "https://example.com/bundle\x7f.json",
				Profile:     federation.ProfileWeb,
				TrustDomain: "example.com",
			},
			wantFailed: true,
			wantContainAny: []string{
				"URL parse error",
				"!MUST NOT include userinfo in the authority component",
			},
		},
		{
			// §5.2 defines exactly two profiles; anything else leaves a client
			// with no way to authenticate the endpoint.
			name: "unknown profile rejected",
			cfg: federation.Config{
				URL:         "https://example.com/bundle.json",
				Profile:     "https_mtls",
				TrustDomain: "example.com",
			},
			wantFailed:     true,
			wantContainAny: []string{`profile="https_mtls"`},
		},
		{
			// An unknown profile has no parameter rules of its own, so the
			// per-profile clauses must stay out of the report entirely rather
			// than guessing which profile was meant.
			name: "unknown profile skips the per-profile clauses",
			cfg: federation.Config{
				URL:         "https://example.com/bundle.json",
				Profile:     "https_mtls",
				TrustDomain: "example.com",
				EndpointID:  "spiffe://example.com/server",
			},
			wantFailed: true,
			wantContainAny: []string{
				"!https_web configuration SHOULD carry no parameters",
				"!https_spiffe configuration MUST set the SPIFFE ID",
			},
		},
		{
			// The trust domain name is checked as a trust domain name, by the
			// same SPIFFE-ID.md clauses a bundle map uses on its keys.
			name: "invalid trust domain name rejected",
			cfg: federation.Config{
				URL:         "https://example.com/bundle.json",
				Profile:     federation.ProfileWeb,
				TrustDomain: "Example.COM",
			},
			wantFailed:     true,
			wantContainAny: []string{`trust_domain: trust_domain="Example.COM"`},
		},
		{
			// §5.2.2.2's mandatory addition.
			name: "https_spiffe without an endpoint SPIFFE ID",
			cfg: federation.Config{
				URL:         "https://example.com/bundle.json",
				Profile:     federation.ProfileSPIFFE,
				TrustDomain: "example.com",
			},
			wantFailed:     true,
			wantContainAny: []string{"endpoint SPIFFE ID not set"},
		},
		{
			// The endpoint SPIFFE ID gets the full SPIFFE-ID.md sweep, so a
			// malformed one fails on the ID clauses rather than silently.
			name: "malformed endpoint SPIFFE ID rejected",
			cfg: federation.Config{
				URL:         "https://example.com/bundle.json",
				Profile:     federation.ProfileSPIFFE,
				TrustDomain: "example.com",
				EndpointID:  "https://example.com/spiffe-bundle-server",
			},
			wantFailed:     true,
			wantContainAny: []string{`scheme="https"`},
		},
		{
			// Figure 3: self-serving, so the configuration carries the bundle
			// that bootstraps the first connection. Without it, warn.
			name: "self-serving https_spiffe without a bootstrap bundle warns",
			cfg: federation.Config{
				URL:         "https://example.com/global/bundle.json",
				Profile:     federation.ProfileSPIFFE,
				TrustDomain: "example.com",
				EndpointID:  "spiffe://example.com/spiffe-bundle-server",
			},
			wantFailed: false,
			wantContainAny: []string{
				"WARN",
				`self-serving endpoint in "example.com", no bootstrap bundle configured`,
			},
		},
		{
			// A non-self-serving endpoint is configured for the server's trust
			// domain separately (§5.2.2.2), which one configuration cannot
			// show, so the clause must not appear at all — neither as a pass
			// nor as a warning.
			name: "non-self-serving endpoint gets no bootstrap-bundle assertion",
			cfg: federation.Config{
				URL:         "https://example.com/production/bundle.json",
				Profile:     federation.ProfileSPIFFE,
				TrustDomain: "prod.example.com",
				EndpointID:  "spiffe://example.com/spiffe-bundle-server",
			},
			wantFailed:     false,
			wantContainAny: []string{"!SHOULD be configured with a bootstrap bundle"},
		},
		{
			// §5.2.1.2: https_web needs nothing beyond the three common
			// parameters, so an endpoint SPIFFE ID here is the tell-tale of a
			// profile set to the wrong value.
			name: "https_web carrying https_spiffe parameters warns",
			cfg: federation.Config{
				URL:         "https://example.com/bundle.json",
				Profile:     federation.ProfileWeb,
				TrustDomain: "example.com",
				EndpointID:  "spiffe://example.com/spiffe-bundle-server",
			},
			wantFailed: false,
			wantContainAny: []string{
				"WARN",
				"endpoint SPIFFE ID set; did this endpoint mean profile https_spiffe?",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &report.Report{}
			if err := federation.Check(r, tc.cfg); err != nil {
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
				// A "!" prefix asserts the substring is absent, which is how
				// the clauses that must stay silent are pinned down.
				if want, ok := strings.CutPrefix(sub, "!"); ok {
					if strings.Contains(out, want) {
						t.Errorf("report contains %q but should not\nreport:\n%s", want, out)
					}
					continue
				}
				if !strings.Contains(out, sub) {
					t.Errorf("report missing %q\nreport:\n%s", sub, out)
				}
			}
		})
	}
}

// TestCheckBootstrapBundle covers the one place this checker reads a file: the
// bootstrap bundle a self-serving https_spiffe endpoint is configured with. It
// is handed to internal/bundle verbatim, so the bundle clauses must fire and
// name the bundle in their detail.
func TestCheckBootstrapBundle(t *testing.T) {
	write := func(t *testing.T, contents string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "bundle.json")
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	selfServing := func(path string) federation.Config {
		return federation.Config{
			URL:         "https://example.com/bundle.json",
			Profile:     federation.ProfileSPIFFE,
			TrustDomain: "example.com",
			EndpointID:  "spiffe://example.com/spiffe-bundle-server",
			BundlePath:  path,
		}
	}

	t.Run("valid bundle satisfies the bootstrap clause", func(t *testing.T) {
		path := write(t, `{
			"spiffe_sequence": 1,
			"spiffe_refresh_hint": 300,
			"keys": [{"kty": "RSA", "kid": "jwt-1", "use": "jwt-svid", "n": "abc", "e": "AQAB"}]
		}`)
		r := &report.Report{}
		if err := federation.Check(r, selfServing(path)); err != nil {
			t.Fatalf("Check error: %v", err)
		}
		var buf strings.Builder
		r.Write(&buf)
		out := buf.String()
		if r.Failed() {
			t.Fatalf("Failed()=true, want false\nreport:\n%s", out)
		}
		if !strings.Contains(out, path) {
			t.Errorf("bootstrap clause does not name the bundle\nreport:\n%s", out)
		}
	})

	t.Run("bundle failures are attributed to the endpoint bundle", func(t *testing.T) {
		path := write(t, `{"spiffe_sequence": 1, "keys": [{"kty": "RSA", "use": "jwt-svid"}]}`)
		r := &report.Report{}
		if err := federation.Check(r, selfServing(path)); err != nil {
			t.Fatalf("Check error: %v", err)
		}
		var buf strings.Builder
		r.Write(&buf)
		out := buf.String()
		if !r.Failed() {
			t.Fatalf("Failed()=false, want true\nreport:\n%s", out)
		}
		if !strings.Contains(out, "endpoint bundle.keys[0]: kid absent") {
			t.Errorf("bundle failure not attributed to the endpoint bundle\nreport:\n%s", out)
		}
	})

	t.Run("unreadable bundle is a hard error", func(t *testing.T) {
		cfg := selfServing(filepath.Join(t.TempDir(), "missing.json"))
		if err := federation.Check(&report.Report{}, cfg); err == nil {
			t.Error("expected an error for a missing bundle file")
		}
	})

	t.Run("malformed bundle is a hard error", func(t *testing.T) {
		cfg := selfServing(write(t, `{"keys": [`))
		err := federation.Check(&report.Report{}, cfg)
		if err == nil || !strings.Contains(err.Error(), "not valid JSON") {
			t.Errorf("error = %v, want a JSON error", err)
		}
	})

	t.Run("a bundle configured without an endpoint SPIFFE ID is still checked", func(t *testing.T) {
		// The §5.2.2.2 MUST already failed, but the bundle that is present has
		// no reason to go unchecked — the checker records the failure and
		// keeps evaluating.
		cfg := selfServing(write(t, `{"spiffe_sequence": 1, "keys": [{"kty": "RSA", "use": "jwt-svid"}]}`))
		cfg.EndpointID = ""
		r := &report.Report{}
		if err := federation.Check(r, cfg); err != nil {
			t.Fatalf("Check error: %v", err)
		}
		var buf strings.Builder
		r.Write(&buf)
		out := buf.String()
		if !strings.Contains(out, "endpoint SPIFFE ID not set") {
			t.Errorf("report missing the §5.2.2.2 failure\nreport:\n%s", out)
		}
		if !strings.Contains(out, "endpoint bundle.keys[0]: kid absent") {
			t.Errorf("bundle was not checked\nreport:\n%s", out)
		}
	})

	t.Run("https_web ignores the bundle beyond the extra-parameter warning", func(t *testing.T) {
		cfg := selfServing(write(t, `{"spiffe_sequence": 1, "keys": [{"kty": "RSA", "use": "jwt-svid"}]}`))
		cfg.Profile = federation.ProfileWeb
		cfg.EndpointID = ""
		r := &report.Report{}
		if err := federation.Check(r, cfg); err != nil {
			t.Fatalf("Check error: %v", err)
		}
		var buf strings.Builder
		r.Write(&buf)
		out := buf.String()
		if !strings.Contains(out, "endpoint bundle set; did this endpoint mean profile https_spiffe?") {
			t.Errorf("report missing the §5.2.1.2 warning\nreport:\n%s", out)
		}
		if strings.Contains(out, "endpoint bundle.keys[0]") {
			t.Errorf("https_web must not check an endpoint bundle it has no use for\nreport:\n%s", out)
		}
	})
}
