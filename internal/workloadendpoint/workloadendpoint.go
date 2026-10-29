// Package workloadendpoint checks a SPIFFE Workload Endpoint address — the
// value of the SPIFFE_ENDPOINT_SOCKET environment variable — against
// SPIFFE_Workload_Endpoint.md §4, which fixes its shape as an RFC 3986 URI with
// a "unix" or "tcp" scheme.
//
// The address is the only static artifact in that spec. Everything it says
// about what happens once a client dials it — gRPC, the workload.spiffe.io
// metadata header, error codes, server reflection — is runtime and stays out
// of scope. The URI walk itself is shared with the Broker Endpoint and lives
// in socketuri; this package supplies the Workload Endpoint's clauses.
package workloadendpoint

import (
	"github.com/kanywst/spiffe-compliance-checker/internal/report"
	"github.com/kanywst/spiffe-compliance-checker/internal/socketuri"
	"github.com/kanywst/spiffe-compliance-checker/internal/spec"
)

// EnvVar is the well-known environment variable §4 says conforming clients
// fall back to when they are not explicitly configured.
const EnvVar = "SPIFFE_ENDPOINT_SOCKET"

// clauses is §4's URI shape, with the host restricted to an IP address and
// §3's limit on TCP transport applied to it.
var clauses = socketuri.Clauses{
	URI:                   spec.WEURI,
	Scheme:                spec.WEScheme,
	UnixNoAuthority:       spec.WEUnixNoAuthority,
	UnixAbsolutePath:      spec.WEUnixAbsolutePath,
	UnixNoOtherComponents: spec.WEUnixNoOtherComponents,
	TCPHost:               spec.WETCPHostIP,
	TCPPort:               spec.WETCPPort,
	TCPNoOtherComponents:  spec.WETCPNoOtherComponents,
	TCPLocalHost:          &spec.WETCPLocalHost,
}

// Check evaluates s against SPIFFE_Workload_Endpoint.md §4 (and the §3 limit on
// TCP transport) and appends the assertions to r.
func Check(r *report.Report, s string) {
	socketuri.Check(r, s, clauses)
}
