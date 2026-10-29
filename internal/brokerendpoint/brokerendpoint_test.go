package brokerendpoint_test

import (
	"strings"
	"testing"

	"github.com/kanywst/spiffe-compliance-checker/internal/brokerendpoint"
	"github.com/kanywst/spiffe-compliance-checker/internal/report"
)

func TestCheck(t *testing.T) {
	cases := []struct {
		name           string
		in             string
		wantFailed     bool
		wantContainAny []string
	}{
		{
			// §4's own examples.
			name:           "valid unix socket",
			in:             "unix:///path/to/endpoint.sock",
			wantContainAny: []string{"SPIFFE_Broker_Endpoint.md", "!SPIFFE_Workload_Endpoint.md"},
		},
		{
			name: "valid tcp socket on an IP address",
			in:   "tcp://127.0.0.1:8000",
		},
		{
			name:           "valid tcp socket on a DNS name",
			in:             "tcp://broker.example.com:8443",
			wantContainAny: []string{"broker.example.com"},
		},
		{
			// The broker may be remote, so there is no locality warning.
			name:           "routable IP does not warn",
			in:             "tcp://10.0.0.5:8443",
			wantContainAny: []string{"!WARN", "!loopback"},
		},
		{
			name: "single-label DNS name",
			in:   "tcp://broker:8443",
		},
		{
			name: "fully qualified DNS name with a trailing dot",
			in:   "tcp://broker.example.com.:8443",
		},
		{
			name: "bracketed IPv6",
			in:   "tcp://[::1]:8443",
		},
		{
			// §4's own invalid example.
			name:           "tcp path rejected",
			in:             "tcp://127.0.0.1:8000/foo",
			wantFailed:     true,
			wantContainAny: []string{`path="/foo" set`},
		},
		{
			name:           "DNS name without a port",
			in:             "tcp://broker.example.com",
			wantFailed:     true,
			wantContainAny: []string{"port not set"},
		},
		{
			name:           "underscore is not a DNS host name character",
			in:             "tcp://bro_ker.example.com:8443",
			wantFailed:     true,
			wantContainAny: []string{"neither an IP address nor a DNS name"},
		},
		{
			name:           "label starting with a hyphen",
			in:             "tcp://-broker.example.com:8443",
			wantFailed:     true,
			wantContainAny: []string{"neither an IP address nor a DNS name"},
		},
		{
			name:           "empty label",
			in:             "tcp://broker..example.com:8443",
			wantFailed:     true,
			wantContainAny: []string{"neither an IP address nor a DNS name"},
		},
		{
			name:           "label over 63 bytes",
			in:             "tcp://" + strings.Repeat("a", 64) + ".example.com:8443",
			wantFailed:     true,
			wantContainAny: []string{"neither an IP address nor a DNS name"},
		},
		{
			// An all-numeric last label is a mistyped IPv4 address.
			name:           "out-of-range dotted quad",
			in:             "tcp://999.0.0.1:8443",
			wantFailed:     true,
			wantContainAny: []string{"neither an IP address nor a DNS name"},
		},
		{
			// A DNS name has no percent-encoding. url.Parse refuses this
			// one outright; socketuri also checks the raw authority in case
			// a Go release lets it through unescaped.
			name:           "percent-encoded host",
			in:             "tcp://bro%6Bker.example.com:8443",
			wantFailed:     true,
			wantContainAny: []string{"URI parse error"},
		},
		{
			name:           "userinfo rejected",
			in:             "tcp://user@broker.example.com:8443",
			wantFailed:     true,
			wantContainAny: []string{"userinfo set"},
		},
		{
			name:           "unix authority rejected",
			in:             "unix://tmp/broker.sock",
			wantFailed:     true,
			wantContainAny: []string{`authority="tmp"`},
		},
		{
			name:           "unknown scheme",
			in:             "https://broker.example.com:8443",
			wantFailed:     true,
			wantContainAny: []string{`scheme="https"`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &report.Report{}
			brokerendpoint.Check(r, tc.in)
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
