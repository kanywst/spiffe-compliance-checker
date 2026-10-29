// Package socketuri checks an endpoint socket address — an RFC 3986 URI with a
// "unix" or "tcp" scheme — against a set of clauses supplied by the caller.
//
// SPIFFE_Workload_Endpoint.md §4 and SPIFFE_Broker_Endpoint.md §4 define the
// same shape almost word for word, and differ only in what a tcp host may be
// and in whether a non-local host is restricted. Each spec's package owns its
// clauses and hands them in as a Clauses value, so every assertion still cites
// the spec it came from. Like jose, this package knows the shape but no spec.
package socketuri

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/kanywst/spiffe-compliance-checker/internal/report"
	"github.com/kanywst/spiffe-compliance-checker/internal/spec"
)

// Clauses is one spec's version of the socket URI rules.
type Clauses struct {
	URI                   spec.Clause
	Scheme                spec.Clause
	UnixNoAuthority       spec.Clause
	UnixAbsolutePath      spec.Clause
	UnixNoOtherComponents spec.Clause
	TCPHost               spec.Clause
	TCPPort               spec.Clause
	TCPNoOtherComponents  spec.Clause
	// TCPLocalHost, when set, is checked against an IP host: the Workload
	// Endpoint's §3 limits TCP to networks that authenticate by source IP.
	TCPLocalHost *spec.Clause
	// AllowDNSName lets a tcp host be a DNS name as well as an IP address.
	AllowDNSName bool
}

// Check evaluates s against c and appends the assertions to r.
func Check(r *report.Report, s string, c Clauses) {
	u, err := url.Parse(s)
	if err != nil {
		// A URI that will not parse leaves no components to inspect.
		r.Fail(c.URI, fmt.Sprintf("URI parse error: %v", err))
		return
	}
	// url.Parse is more lenient than RFC 3986: it lets a space or a raw
	// non-ASCII byte through ("unix:///run/my agent.sock"), so a successful
	// parse alone does not show the value is a URI. Such a value still has
	// components worth checking, so this is a soft failure.
	if i, b, ok := firstNonURIByte(s); ok {
		r.Fail(c.URI, fmt.Sprintf("byte %q at offset %d must be percent-encoded", b, i))
	} else {
		r.Pass(c.URI, "")
	}

	// RFC 3986 makes the scheme case-insensitive; url.Parse already lowercases
	// u.Scheme, so "UNIX" lands here as "unix".
	switch u.Scheme {
	case "unix":
		r.Pass(c.Scheme, "unix")
		checkUnix(r, s, u, c)
	case "tcp":
		r.Pass(c.Scheme, "tcp")
		checkTCP(r, s, u, c)
	default:
		// The remaining clauses are all per-scheme, so an unknown scheme has
		// nothing left to check.
		r.Fail(c.Scheme, fmt.Sprintf("scheme=%q", u.Scheme))
	}
}

func checkUnix(r *report.Report, s string, u *url.URL, c Clauses) {
	// u.Host carries any port too, so this covers every part of an authority.
	// "unix:///path" parses to an empty authority, which §4 itself uses as its
	// example, so only a non-empty one is a violation.
	if u.User != nil || u.Host != "" {
		r.Fail(c.UnixNoAuthority, fmt.Sprintf("authority=%q", authority(u)))
	} else {
		r.Pass(c.UnixNoAuthority, "")
	}

	switch {
	case u.Opaque != "":
		// "unix:relative/path" parses as an opaque URI with no path at all.
		r.Fail(c.UnixAbsolutePath, fmt.Sprintf("path=%q is not absolute", u.Opaque))
	case u.Path == "":
		r.Fail(c.UnixAbsolutePath, "path not set")
	default:
		r.Pass(c.UnixAbsolutePath, u.Path)
	}

	// The authority already has a clause of its own, so only query and
	// fragment are left for "no other component may be set".
	if extra := queryFragment(s); len(extra) > 0 {
		r.Fail(c.UnixNoOtherComponents, strings.Join(extra, ", ")+" set")
	} else {
		r.Pass(c.UnixNoOtherComponents, "")
	}
}

func checkTCP(r *report.Report, s string, u *url.URL, c Clauses) {
	addr, hostOK := checkTCPHost(r, u, c)
	checkTCPPort(r, u, c)

	var extra []string
	if u.User != nil {
		extra = append(extra, "userinfo")
	}
	if u.Path != "" {
		extra = append(extra, fmt.Sprintf("path=%q", u.Path))
	}
	extra = append(extra, queryFragment(s)...)
	if len(extra) > 0 {
		r.Fail(c.TCPNoOtherComponents, strings.Join(extra, ", ")+" set")
	} else {
		r.Pass(c.TCPNoOtherComponents, "")
	}

	if c.TCPLocalHost == nil || !hostOK {
		// Without an IP address there is no host to judge the §3 limit by.
		return
	}
	switch a := addr.Unmap(); {
	case a.IsLoopback() || a.IsLinkLocalUnicast():
		r.Pass(*c.TCPLocalHost, addr.String())
	case a.IsUnspecified():
		// 0.0.0.0 and :: fail §3's test like any other non-local host. The
		// note after it is scc's own observation, not a §3 finding: they name
		// "every interface" for a listener, not a place a client can dial,
		// which makes them the likeliest server-side value to leak into a
		// client's environment.
		r.Fail(*c.TCPLocalHost, fmt.Sprintf("host=%q is neither loopback nor link-local, and scc cannot see network-level assertions (scc note: the unspecified address is a listener wildcard, not an address a client dials)", addr.String()))
	default:
		r.Fail(*c.TCPLocalHost, fmt.Sprintf("host=%q is neither loopback nor link-local, and scc cannot see network-level assertions", addr.String()))
	}
}

// checkTCPHost returns the host's address when it is an IP address; a DNS
// name, where allowed, passes but returns false, since it has no address to
// judge locality by.
func checkTCPHost(r *report.Report, u *url.URL, c Clauses) (netip.Addr, bool) {
	if u.Opaque != "" {
		// "tcp:127.0.0.1:8000" has no "//", so it carries no authority at all.
		r.Fail(c.TCPHost, "authority not set")
		return netip.Addr{}, false
	}
	host := u.Hostname()
	if host == "" {
		r.Fail(c.TCPHost, "host not set")
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		switch {
		case !c.AllowDNSName:
			r.Fail(c.TCPHost, fmt.Sprintf("host=%q is not an IP address", host))
		case strings.HasPrefix(u.Host, "[") || strings.Contains(u.Host, "%") || !isDNSName(host):
			// url.Parse rejects a percent-encoded host today, but its
			// strictness differs between Go releases (see the bare-IPv6
			// case below), and it would unescape one it accepted, so the
			// raw authority is checked rather than leaning on it.
			r.Fail(c.TCPHost, fmt.Sprintf("host=%q is neither an IP address nor a DNS name", host))
		default:
			r.Pass(c.TCPHost, host)
		}
		return netip.Addr{}, false
	}
	// url.Parse accepts a bare IPv6 address in the authority and splits it at
	// the last colon, so "tcp://fe80::1:8000" would otherwise pass with port
	// 8000 — though fe80::1:8000 is itself a complete address. RFC 3986
	// §3.2.2 only admits IPv6 as a bracketed IP-literal.
	if addr.Is6() && !strings.HasPrefix(u.Host, "[") {
		r.Fail(c.TCPHost, fmt.Sprintf("host=%q is an IPv6 address without the [ ] RFC 3986 requires", host))
		return netip.Addr{}, false
	}
	// RFC 3986's IP-literal has no zone; zones in URIs come from RFC 6874,
	// which §4 does not cite. go-spiffe's net.ParseIP rejects them too, so a
	// zoned address is one the reference client will not dial.
	// The converse: brackets are only for IPv6 (and IPvFuture) literals.
	// url.Parse rejects "[127.0.0.1]" today, but the bare-IPv6 case above
	// shows its strictness differs between Go releases, so this does not
	// lean on it.
	if !addr.Is6() && strings.HasPrefix(u.Host, "[") {
		r.Fail(c.TCPHost, fmt.Sprintf("host=%q is an IPv4 address in [ ], which RFC 3986 reserves for IPv6", host))
		return netip.Addr{}, false
	}
	if addr.Zone() != "" {
		r.Fail(c.TCPHost, fmt.Sprintf("host=%q carries an IPv6 zone, which an RFC 3986 IP-literal cannot", host))
		return netip.Addr{}, false
	}
	r.Pass(c.TCPHost, host)
	return addr, true
}

func checkTCPPort(r *report.Report, u *url.URL, c Clauses) {
	if u.Opaque != "" {
		// No authority means no port either, so this fails alongside
		// WETCPHostIP, the same way "tcp://" fails both.
		r.Fail(c.TCPPort, "authority not set")
		return
	}
	port := u.Port()
	if port == "" {
		// Also the "tcp://127.0.0.1:" case, where u.Port() drops the colon.
		r.Fail(c.TCPPort, "port not set")
		return
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		r.Fail(c.TCPPort, fmt.Sprintf("port=%q is not a TCP port number", port))
		return
	}
	// §4 asks for the port of the listen socket, and a bound listen socket
	// never has port 0 — 0 only asks the OS to choose one. The clause text
	// carries that wording, so the detail says which part of it fails.
	if n == 0 {
		r.Fail(c.TCPPort, fmt.Sprintf("port=%q is not the port of a listen socket (port 0 only asks the OS to choose one)", port))
		return
	}
	r.Pass(c.TCPPort, port)
}

// isDNSName reports whether host is a DNS host name in the RFC 1123 sense:
// dot-separated labels of letters, digits and hyphens, 1-63 bytes each, not
// starting or ending with a hyphen, at most 253 bytes in all. One trailing dot
// (a fully qualified name) is accepted. An all-numeric last label is refused,
// as RFC 3696 §2 does for top-level domains: "999.0.0.1" is a mistyped IPv4
// address, not a name.
func isDNSName(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		if strings.Trim(l, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-") != "" {
			return false
		}
	}
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
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
