package workloadendpoint_test

import (
	"strings"
	"testing"

	"github.com/kanywst/spiffe-compliance-checker/internal/report"
	"github.com/kanywst/spiffe-compliance-checker/internal/workloadendpoint"
)

func TestCheck(t *testing.T) {
	cases := []struct {
		name           string
		in             string
		wantFailed     bool
		wantContainAny []string
	}{
		{
			// §4's own unix example.
			name:           "valid unix socket",
			in:             "unix:///path/to/endpoint.sock",
			wantFailed:     false,
			wantContainAny: []string{"/path/to/endpoint.sock", "!WARN"},
		},
		{
			// No "//" means no authority at all, which is just as compliant.
			name:       "unix socket without an empty authority",
			in:         "unix:/run/spire/agent.sock",
			wantFailed: false,
		},
		{
			// §4's own tcp example.
			name:           "valid tcp socket",
			in:             "tcp://127.0.0.1:8000",
			wantFailed:     false,
			wantContainAny: []string{"127.0.0.1", "8000", "!WARN"},
		},
		{
			name:       "valid tcp socket on IPv6 loopback",
			in:         "tcp://[::1]:8000",
			wantFailed: false,
		},
		{
			name:           "valid tcp socket on IPv6 link-local",
			in:             "tcp://[fe80::1]:8000",
			wantFailed:     false,
			wantContainAny: []string{"!WARN"},
		},
		{
			// RFC 3986's IP-literal has no zone, and go-spiffe will not dial
			// one either.
			name:           "tcp IPv6 zone rejected",
			in:             "tcp://[fe80::1%25eth0]:8000",
			wantFailed:     true,
			wantContainAny: []string{"carries an IPv6 zone"},
		},
		{
			// Some Go releases (1.26.0) reject a bare IPv6 authority in
			// url.Parse; others (1.26.8, 1.27) accept it and split at the last
			// colon, reading fe80::1:8000 as host fe80::1, port 8000. Either
			// way the value must fail and must never reach the §3 judgement,
			// so the assertions avoid the message that differs.
			name:           "tcp unbracketed IPv6 link-local rejected",
			in:             "tcp://fe80::1:8000",
			wantFailed:     true,
			wantContainAny: []string{"!localhost or link-local"},
		},
		{
			name:           "tcp unbracketed IPv6 loopback rejected",
			in:             "tcp://::1:8000",
			wantFailed:     true,
			wantContainAny: []string{"!localhost or link-local"},
		},
		{
			name:           "uppercase scheme accepted",
			in:             "UNIX:///tmp/agent.sock",
			wantFailed:     false,
			wantContainAny: []string{`scheme MUST be set to either "unix" or "tcp"`},
		},
		{
			// An unknown scheme leaves every per-scheme clause without
			// anything to say, so none of them may appear.
			name:       "unknown scheme rejected alone",
			in:         "http://127.0.0.1:8000",
			wantFailed: true,
			wantContainAny: []string{
				`scheme="http"`,
				"!tcp: ",
				"!unix: ",
			},
		},
		{
			// A bare path is the most common misconfiguration: it is a socket
			// location, but not a URI.
			name:           "bare path rejected",
			in:             "/tmp/agent.sock",
			wantFailed:     true,
			wantContainAny: []string{`scheme=""`},
		},
		{
			name:           "empty value rejected",
			in:             "",
			wantFailed:     true,
			wantContainAny: []string{`scheme=""`},
		},
		{
			name:           "unparseable URI reported once",
			in:             "unix:///tmp/agent\x7f.sock",
			wantFailed:     true,
			wantContainAny: []string{"URI parse error", "!authority component MUST NOT be set", `!scheme MUST be set to either "unix" or "tcp"`},
		},
		{
			// "unix://tmp/agent.sock" is the two-slash typo: "tmp" becomes the
			// authority and the path loses its first segment.
			name:           "unix authority rejected",
			in:             "unix://tmp/agent.sock",
			wantFailed:     true,
			wantContainAny: []string{`authority="tmp"`},
		},
		{
			name:           "unix userinfo rejected as authority",
			in:             "unix://user@/tmp/agent.sock",
			wantFailed:     true,
			wantContainAny: []string{`authority="user@"`},
		},
		{
			name:           "unix relative path rejected",
			in:             "unix:tmp/agent.sock",
			wantFailed:     true,
			wantContainAny: []string{`path="tmp/agent.sock" is not absolute`},
		},
		{
			name:           "unix missing path rejected",
			in:             "unix://",
			wantFailed:     true,
			wantContainAny: []string{"path not set"},
		},
		{
			name:           "unix query and fragment rejected",
			in:             "unix:///tmp/agent.sock?x=1#y",
			wantFailed:     true,
			wantContainAny: []string{"query, fragment set"},
		},
		{
			// url.Parse forgets an empty fragment, so this one is only
			// visible in the raw string.
			name:           "unix empty fragment rejected",
			in:             "unix:///tmp/agent.sock#",
			wantFailed:     true,
			wantContainAny: []string{"fragment set"},
		},
		{
			// The scheme is fine; only the URI is broken, and the report must
			// cite that rather than the scheme clause.
			name:           "invalid escape blamed on the URI, not the scheme",
			in:             "unix://%zz/p",
			wantFailed:     true,
			wantContainAny: []string{"RFC 3986 URI", "URI parse error", `!scheme MUST be set to either "unix" or "tcp"`},
		},
		{
			// Brackets are for IPv6 / IPvFuture only (RFC 3986 §3.2.2).
			// url.Parse rejects this today and the checker rejects it on its
			// own otherwise, so only the shared outcome is asserted: it fails
			// and never reaches the §3 judgement.
			name:           "tcp bracketed IPv4 rejected",
			in:             "tcp://[127.0.0.1]:8000",
			wantFailed:     true,
			wantContainAny: []string{"!localhost or link-local"},
		},
		{
			// url.Parse accepts both; RFC 3986 requires them percent-encoded.
			name:           "unix unencoded space rejected",
			in:             "unix:///run/my agent.sock",
			wantFailed:     true,
			wantContainAny: []string{`byte ' ' at offset 14 must be percent-encoded`, "/run/my agent.sock"},
		},
		{
			name:           "unix raw non-ASCII byte rejected",
			in:             "unix:///run/\u00e9.sock",
			wantFailed:     true,
			wantContainAny: []string{"at offset 12 must be percent-encoded"},
		},
		{
			name:       "unix percent-encoded space accepted",
			in:         "unix:///run/my%20agent.sock",
			wantFailed: false,
		},
		{
			// A listen-side wildcard leaking into a client's environment.
			name:           "tcp unspecified address warns",
			in:             "tcp://0.0.0.0:8000",
			wantFailed:     false,
			wantContainAny: []string{"WARN", "unspecified address"},
		},
		{
			name:           "tcp IPv6 unspecified address warns",
			in:             "tcp://[::]:8000",
			wantFailed:     false,
			wantContainAny: []string{"WARN", "unspecified address"},
		},
		{
			// A "?" inside the fragment is fragment text, not a query.
			name:           "unix question mark inside the fragment is not a query",
			in:             "unix:///tmp/agent.sock#x?y",
			wantFailed:     true,
			wantContainAny: []string{"→ fragment set"},
		},
		{
			name:           "unix empty query rejected",
			in:             "unix:///tmp/agent.sock?",
			wantFailed:     true,
			wantContainAny: []string{"query set"},
		},
		{
			name:           "tcp hostname rejected",
			in:             "tcp://localhost:8000",
			wantFailed:     true,
			wantContainAny: []string{`host="localhost" is not an IP address`},
		},
		{
			name:           "tcp missing port rejected",
			in:             "tcp://127.0.0.1",
			wantFailed:     true,
			wantContainAny: []string{"port not set"},
		},
		{
			name:           "tcp trailing colon rejected",
			in:             "tcp://127.0.0.1:",
			wantFailed:     true,
			wantContainAny: []string{"port not set"},
		},
		{
			name:           "tcp port zero rejected",
			in:             "tcp://127.0.0.1:0",
			wantFailed:     true,
			wantContainAny: []string{`port="0" is not the port of a listen socket`},
		},
		{
			name:           "tcp port out of range rejected",
			in:             "tcp://127.0.0.1:70000",
			wantFailed:     true,
			wantContainAny: []string{`port="70000" is not a TCP port number`},
		},
		{
			// §4's own counter-example.
			name:           "tcp path rejected",
			in:             "tcp://127.0.0.1:8000/foo",
			wantFailed:     true,
			wantContainAny: []string{`path="/foo" set`},
		},
		{
			name:           "tcp userinfo, query and fragment rejected",
			in:             "tcp://user@127.0.0.1:8000?x#y",
			wantFailed:     true,
			wantContainAny: []string{"userinfo, query, fragment set"},
		},
		{
			name:       "tcp without authority rejected",
			in:         "tcp:127.0.0.1:8000",
			wantFailed: true,
			wantContainAny: []string{
				"authority not set",
				// No host means no §3 judgement either.
				"!localhost or link-local",
			},
		},
		{
			// §3 permits a routable address behind network-level
			// authentication no URI can show, so this is only a warning.
			name:           "tcp routable host warns",
			in:             "tcp://10.0.0.5:8000",
			wantFailed:     false,
			wantContainAny: []string{"WARN", `host="10.0.0.5"`},
		},
		{
			name:           "tcp IPv4-mapped loopback is loopback",
			in:             "tcp://[::ffff:127.0.0.1]:8000",
			wantFailed:     false,
			wantContainAny: []string{"!WARN"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &report.Report{}
			workloadendpoint.Check(r, tc.in)
			// Render unconditionally: some cases assert on WARN text, which
			// leaves Failed() false.
			var buf strings.Builder
			r.Write(&buf)
			out := buf.String()

			if got := r.Failed(); got != tc.wantFailed {
				t.Fatalf("Failed()=%v, want %v\nreport:\n%s", got, tc.wantFailed, out)
			}
			for _, sub := range tc.wantContainAny {
				// A "!" prefix asserts the substring is absent.
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
