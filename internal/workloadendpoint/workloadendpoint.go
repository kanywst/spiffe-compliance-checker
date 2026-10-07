// Package workloadendpoint checks a SPIFFE Workload Endpoint address — the
// value of the SPIFFE_ENDPOINT_SOCKET environment variable — against
// SPIFFE_Workload_Endpoint.md §4, which fixes its shape as an RFC 3986 URI with
// a "unix" or "tcp" scheme.
//
// The address is the only static artifact in that spec. Everything it says
// about what happens once a client dials it — gRPC, the workload.spiffe.io
// metadata header, error codes, server reflection — is runtime and stays out
// of scope.
package workloadendpoint

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/kanywst/spiffe-compliance-checker/internal/report"
	"github.com/kanywst/spiffe-compliance-checker/internal/spec"
)

// EnvVar is the well-known environment variable §4 says conforming clients
// fall back to when they are not explicitly configured.
const EnvVar = "SPIFFE_ENDPOINT_SOCKET"

// Check evaluates s against SPIFFE_Workload_Endpoint.md §4 (and the §3 limit on
// TCP transport) and appends the assertions to r.
func Check(r *report.Report, s string) {
	u, err := url.Parse(s)
	if err != nil {
		// A URI that will not parse leaves no components to inspect.
		r.Fail(spec.WEURI, fmt.Sprintf("URI parse error: %v", err))
		return
	}
	// url.Parse is more lenient than RFC 3986: it lets a space or a raw
	// non-ASCII byte through ("unix:///run/my agent.sock"), so a successful
	// parse alone does not show the value is a URI. Such a value still has
	// components worth checking, so this is a soft failure.
	if i, c, ok := firstNonURIByte(s); ok {
		r.Fail(spec.WEURI, fmt.Sprintf("byte %q at offset %d must be percent-encoded", c, i))
	} else {
		r.Pass(spec.WEURI, "")
	}

	// RFC 3986 makes the scheme case-insensitive; url.Parse already lowercases
	// u.Scheme, so "UNIX" lands here as "unix".
	switch u.Scheme {
	case "unix":
		r.Pass(spec.WEScheme, "unix")
		checkUnix(r, s, u)
	case "tcp":
		r.Pass(spec.WEScheme, "tcp")
		checkTCP(r, s, u)
	default:
		// The remaining clauses are all per-scheme, so an unknown scheme has
		// nothing left to check.
		r.Fail(spec.WEScheme, fmt.Sprintf("scheme=%q", u.Scheme))
	}
}

func checkUnix(r *report.Report, s string, u *url.URL) {
	// u.Host carries any port too, so this covers every part of an authority.
	// "unix:///path" parses to an empty authority, which §4 itself uses as its
	// example, so only a non-empty one is a violation.
	if u.User != nil || u.Host != "" {
		r.Fail(spec.WEUnixNoAuthority, fmt.Sprintf("authority=%q", authority(u)))
	} else {
		r.Pass(spec.WEUnixNoAuthority, "")
	}

	switch {
	case u.Opaque != "":
		// "unix:relative/path" parses as an opaque URI with no path at all.
		r.Fail(spec.WEUnixAbsolutePath, fmt.Sprintf("path=%q is not absolute", u.Opaque))
	case u.Path == "":
		r.Fail(spec.WEUnixAbsolutePath, "path not set")
	default:
		r.Pass(spec.WEUnixAbsolutePath, u.Path)
	}

	// The authority already has a clause of its own, so only query and
	// fragment are left for "no other component may be set".
	if extra := queryFragment(s); len(extra) > 0 {
		r.Fail(spec.WEUnixNoOtherComponents, strings.Join(extra, ", ")+" set")
	} else {
		r.Pass(spec.WEUnixNoOtherComponents, "")
	}
}

func checkTCP(r *report.Report, s string, u *url.URL) {
	addr, hostOK := checkTCPHost(r, u)
	checkTCPPort(r, u)

	var extra []string
	if u.User != nil {
		extra = append(extra, "userinfo")
	}
	if u.Path != "" {
		extra = append(extra, fmt.Sprintf("path=%q", u.Path))
	}
	extra = append(extra, queryFragment(s)...)
	if len(extra) > 0 {
		r.Fail(spec.WETCPNoOtherComponents, strings.Join(extra, ", ")+" set")
	} else {
		r.Pass(spec.WETCPNoOtherComponents, "")
	}

	if !hostOK {
		// Without an IP address there is no host to judge the §3 limit by.
		return
	}
	switch a := addr.Unmap(); {
	case a.IsLoopback() || a.IsLinkLocalUnicast():
		r.Pass(spec.WETCPLocalHost, addr.String())
	case a.IsUnspecified():
		// 0.0.0.0 and :: fail §3's test like any other non-local host. The
		// note after it is scc's own observation, not a §3 finding: they name
		// "every interface" for a listener, not a place a client can dial,
		// which makes them the likeliest server-side value to leak into a
		// client's environment.
		r.Fail(spec.WETCPLocalHost, fmt.Sprintf("host=%q is neither loopback nor link-local, and scc cannot see network-level assertions (scc note: the unspecified address is a listener wildcard, not an address a client dials)", addr.String()))
	default:
		r.Fail(spec.WETCPLocalHost, fmt.Sprintf("host=%q is neither loopback nor link-local, and scc cannot see network-level assertions", addr.String()))
	}
}

func checkTCPHost(r *report.Report, u *url.URL) (netip.Addr, bool) {
	if u.Opaque != "" {
		// "tcp:127.0.0.1:8000" has no "//", so it carries no authority at all.
		r.Fail(spec.WETCPHostIP, "authority not set")
		return netip.Addr{}, false
	}
	host := u.Hostname()
	if host == "" {
		r.Fail(spec.WETCPHostIP, "host not set")
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		r.Fail(spec.WETCPHostIP, fmt.Sprintf("host=%q is not an IP address", host))
		return netip.Addr{}, false
	}
	// url.Parse accepts a bare IPv6 address in the authority and splits it at
	// the last colon, so "tcp://fe80::1:8000" would otherwise pass with port
	// 8000 — though fe80::1:8000 is itself a complete address. RFC 3986
	// §3.2.2 only admits IPv6 as a bracketed IP-literal.
	if addr.Is6() && !strings.HasPrefix(u.Host, "[") {
		r.Fail(spec.WETCPHostIP, fmt.Sprintf("host=%q is an IPv6 address without the [ ] RFC 3986 requires", host))
		return netip.Addr{}, false
	}
	// RFC 3986's IP-literal has no zone; zones in URIs come from RFC 6874,
	// which §4 does not cite. go-spiffe's net.ParseIP rejects them too, so a
	// zoned address is one the reference client will not dial.
	if addr.Zone() != "" {
		r.Fail(spec.WETCPHostIP, fmt.Sprintf("host=%q carries an IPv6 zone, which an RFC 3986 IP-literal cannot", host))
		return netip.Addr{}, false
	}
	r.Pass(spec.WETCPHostIP, host)
	return addr, true
}

func checkTCPPort(r *report.Report, u *url.URL) {
	if u.Opaque != "" {
		// No authority means no port either, so this fails alongside
		// WETCPHostIP, the same way "tcp://" fails both.
		r.Fail(spec.WETCPPort, "authority not set")
		return
	}
	port := u.Port()
	if port == "" {
		// Also the "tcp://127.0.0.1:" case, where u.Port() drops the colon.
		r.Fail(spec.WETCPPort, "port not set")
		return
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		r.Fail(spec.WETCPPort, fmt.Sprintf("port=%q is not a TCP port number", port))
		return
	}
	// §4 asks for the port of the listen socket, and a bound listen socket
	// never has port 0 — 0 only asks the OS to choose one. The clause text
	// carries that wording, so the detail says which part of it fails.
	if n == 0 {
		r.Fail(spec.WETCPPort, fmt.Sprintf("port=%q is not the port of a listen socket (port 0 only asks the OS to choose one)", port))
		return
	}
	r.Pass(spec.WETCPPort, port)
}

// firstNonURIByte returns the first byte of s that RFC 3986 §2 does not allow
// to appear unencoded: anything outside unreserved, gen-delims, sub-delims and
// "%". Whether a "%" starts a valid escape is left to url.Parse, which already
// rejects a malformed one.
func firstNonURIByte(s string) (int, byte, bool) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte("-._~:/?#[]@!$&'()*+,;=%", c) >= 0:
		default:
			return i, c, true
		}
	}
	return 0, 0, false
}

// queryFragment reports which of query and fragment s carries. It reads the
// raw string, as id.Check does, because url.Parse drops an empty query or
// fragment ("unix:///p?", "unix:///p#") without a trace. A "?" after the "#"
// belongs to the fragment, so only the part before it can hold a query.
func queryFragment(s string) []string {
	var set []string
	before, _, hasFragment := strings.Cut(s, "#")
	if strings.Contains(before, "?") {
		set = append(set, "query")
	}
	if hasFragment {
		set = append(set, "fragment")
	}
	return set
}

func authority(u *url.URL) string {
	if u.User != nil {
		return u.User.String() + "@" + u.Host
	}
	return u.Host
}
