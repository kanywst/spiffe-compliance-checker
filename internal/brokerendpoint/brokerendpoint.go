// Package brokerendpoint checks a SPIFFE Broker Endpoint address — the value
// of the SPIFFE_BROKER_SOCKET environment variable — against
// SPIFFE_Broker_Endpoint.md §4.
//
// §4 is the only static artifact in that spec. gRPC, the broker.spiffe.io
// metadata header, mutual TLS, authorization and error codes are runtime and
// stay out of scope, as does §2's SHOULD on restricting who can reach the
// endpoint, which no address can show. The URI walk is shared with the
// Workload Endpoint in socketuri; this package supplies the broker's clauses.
package brokerendpoint

import (
	"github.com/kanywst/spiffe-compliance-checker/internal/report"
	"github.com/kanywst/spiffe-compliance-checker/internal/socketuri"
	"github.com/kanywst/spiffe-compliance-checker/internal/spec"
)

// EnvVar is the well-known environment variable §4 says conforming clients
// fall back to when they are not explicitly configured.
const EnvVar = "SPIFFE_BROKER_SOCKET"

// clauses is §4's URI shape. Unlike the Workload Endpoint, a tcp host may be
// a DNS name, and no locality limit applies: §4 explains that the broker "is
// allowed to be served over the network and is authenticated".
var clauses = socketuri.Clauses{
	URI:                   spec.BEURI,
	Scheme:                spec.BEScheme,
	UnixNoAuthority:       spec.BEUnixNoAuthority,
	UnixAbsolutePath:      spec.BEUnixAbsolutePath,
	UnixNoOtherComponents: spec.BEUnixNoOtherComponents,
	TCPHost:               spec.BETCPHost,
	TCPPort:               spec.BETCPPort,
	TCPNoOtherComponents:  spec.BETCPNoOtherComponents,
	AllowDNSName:          true,
}

// Check evaluates s against SPIFFE_Broker_Endpoint.md §4 and appends the
// assertions to r.
func Check(r *report.Report, s string) {
	socketuri.Check(r, s, clauses)
}
