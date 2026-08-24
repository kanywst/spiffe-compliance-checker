package id_test

import (
	"strings"
	"testing"

	"github.com/kanywst/spiffe-compliance-checker/internal/id"
	"github.com/kanywst/spiffe-compliance-checker/internal/report"
)

func TestCheck(t *testing.T) {
	cases := []struct {
		name           string
		in             string
		wantFailed     bool
		wantContainAny []string // substring(s) that must appear in at least one FAIL line
	}{
		{
			name:       "valid leaf ID",
			in:         "spiffe://example.com/payments/web-fe",
			wantFailed: false,
		},
		{
			name:       "valid root ID (signing cert style)",
			in:         "spiffe://example.com",
			wantFailed: false,
		},
		{
			name:           "wrong scheme",
			in:             "https://example.com/foo",
			wantFailed:     true,
			wantContainAny: []string{`scheme MUST be "spiffe"`},
		},
		{
			name:           "uppercase trust domain",
			in:             "spiffe://Example.com/foo",
			wantFailed:     true,
			wantContainAny: []string{"trust domain MUST be lowercase"},
		},
		{
			name:           "userinfo in authority",
			in:             "spiffe://alice@example.com/foo",
			wantFailed:     true,
			wantContainAny: []string{"userinfo"},
		},
		{
			name:           "port in authority",
			in:             "spiffe://example.com:8080/foo",
			wantFailed:     true,
			wantContainAny: []string{"port"},
		},
		{
			name:           "query present",
			in:             "spiffe://example.com/foo?bar=baz",
			wantFailed:     true,
			wantContainAny: []string{"query or fragment"},
		},
		{
			name:           "fragment present",
			in:             "spiffe://example.com/foo#bar",
			wantFailed:     true,
			wantContainAny: []string{"query or fragment"},
		},
		{
			name:           "trailing slash",
			in:             "spiffe://example.com/foo/",
			wantFailed:     true,
			wantContainAny: []string{`trailing "/"`},
		},
		{
			name:           "dot segment",
			in:             "spiffe://example.com/foo/./bar",
			wantFailed:     true,
			wantContainAny: []string{`"." / ".."`},
		},
		{
			name:           "dotdot segment",
			in:             "spiffe://example.com/foo/../bar",
			wantFailed:     true,
			wantContainAny: []string{`"." / ".."`},
		},
		{
			name:           "percent-encoded path",
			in:             "spiffe://example.com/foo%20bar",
			wantFailed:     true,
			wantContainAny: []string{"percent-encoded"},
		},
		{
			name:           "trust domain too long",
			in:             "spiffe://" + strings.Repeat("a", 256) + "/foo",
			wantFailed:     true,
			wantContainAny: []string{"at most 255 bytes"},
		},
		{
			// Regression: u.Hostname() must strip IPv6 brackets so the
			// charset check sees the raw "::1" and rejects it on `:`.
			name:           "IPv6 bracketed trust domain",
			in:             "spiffe://[::1]/foo",
			wantFailed:     true,
			wantContainAny: []string{"trust domain MUST contain only"},
		},
		{
			// Regression: u.Port() is empty for trailing colon, must catch
			// via HasSuffix on u.Host.
			name:           "trailing colon in authority",
			in:             "spiffe://example.com:/foo",
			wantFailed:     true,
			wantContainAny: []string{"trailing colon"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &report.Report{}
			id.Check(r, tc.in)

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

// CheckTrustDomain is the entry point internal/bundlemap uses on a bare trust
// domain name, so it must apply the §2.1/§2.3 clauses without a scheme or path
// and attribute each detail to the caller's tag.
func TestCheckTrustDomain(t *testing.T) {
	cases := []struct {
		name           string
		tag            string
		in             string
		wantFailed     bool
		wantContainAny []string
	}{
		{
			name:       "valid name",
			in:         "example.com",
			wantFailed: false,
		},
		{
			name:           "empty name",
			in:             "",
			wantFailed:     true,
			wantContainAny: []string{"trust domain MUST NOT be empty"},
		},
		{
			name:           "uppercase name is tagged",
			tag:            `trust_domains["Example.com"]`,
			in:             "Example.com",
			wantFailed:     true,
			wantContainAny: []string{`trust_domains["Example.com"]: trust_domain="Example.com"`},
		},
		{
			name:           "name over 255 bytes",
			in:             strings.Repeat("a", 256),
			wantFailed:     true,
			wantContainAny: []string{"len=256"},
		},
		{
			name:           "forbidden character",
			in:             "example.com/foo",
			wantFailed:     true,
			wantContainAny: []string{"only [a-z0-9.-_]"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &report.Report{}
			id.CheckTrustDomain(r, tc.tag, tc.in)

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
