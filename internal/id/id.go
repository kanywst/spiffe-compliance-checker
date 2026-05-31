// Package id implements MUST-clause validation of a SPIFFE ID string against
// SPIFFE-ID.md. It does not require any external dependency and operates on
// the raw URI text so it can be exercised from a string or from the SAN of an
// X.509-SVID or the sub claim of a JWT-SVID.
package id

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/0-draft/spiffe-compliance-checker/internal/report"
	"github.com/0-draft/spiffe-compliance-checker/internal/spec"
)

// Check evaluates the MUST/SHOULD clauses defined in SPIFFE-ID.md against s
// and appends the assertions to r.
func Check(r *report.Report, s string) {
	if strings.Contains(s, "?") {
		r.Fail(spec.IDNoQueryFragment, "found '?' in input")
		return
	}
	if strings.Contains(s, "#") {
		r.Fail(spec.IDNoQueryFragment, "found '#' in input")
		return
	}
	r.Pass(spec.IDNoQueryFragment, "")

	u, err := url.Parse(s)
	if err != nil {
		r.Fail(spec.IDSchemeSpiffe, fmt.Sprintf("URL parse error: %v", err))
		return
	}

	checkScheme(r, u)
	checkAuthority(r, u)
	checkPath(r, u)
	checkLength(r, s)
}

func checkScheme(r *report.Report, u *url.URL) {
	// §2.4: scheme is case-insensitive, but §2.1 says canonical form is
	// lowercase. We compare case-insensitively here and let the trust domain
	// check enforce the lowercase requirement on the authority component.
	if !strings.EqualFold(u.Scheme, "spiffe") {
		r.Fail(spec.IDSchemeSpiffe, fmt.Sprintf("scheme=%q", u.Scheme))
		return
	}
	r.Pass(spec.IDSchemeSpiffe, "")
}

func checkAuthority(r *report.Report, u *url.URL) {
	host := u.Hostname()
	port := u.Port()

	if u.User != nil {
		r.Fail(spec.IDNoUserinfo, "userinfo present in authority")
	} else {
		r.Pass(spec.IDNoUserinfo, "")
	}

	switch {
	case port != "":
		r.Fail(spec.IDNoPort, fmt.Sprintf("port=%q", port))
	case strings.HasSuffix(u.Host, ":"):
		// e.g. "spiffe://example.com:" — u.Port() returns "" but the
		// authority still has the trailing colon, which the spec forbids.
		r.Fail(spec.IDNoPort, "authority has trailing colon")
	default:
		r.Pass(spec.IDNoPort, "")
	}

	if host == "" {
		r.Fail(spec.IDTrustDomainNonEmpty, "")
		return
	}
	r.Pass(spec.IDTrustDomainNonEmpty, "")

	if host != strings.ToLower(host) {
		r.Fail(spec.IDTrustDomainLowercase, fmt.Sprintf("trust_domain=%q", host))
	} else {
		r.Pass(spec.IDTrustDomainLowercase, "")
	}

	if !isTrustDomainCharset(host) {
		r.Fail(spec.IDTrustDomainCharset, fmt.Sprintf("trust_domain=%q", host))
	} else {
		r.Pass(spec.IDTrustDomainCharset, "")
	}

	// §2.3: trust domain at most 255 bytes.
	if len(host) > 255 {
		r.Fail(spec.IDTrustDomainLengthLimit, fmt.Sprintf("len=%d", len(host)))
	} else {
		r.Pass(spec.IDTrustDomainLengthLimit, "")
	}
}

func checkPath(r *report.Report, u *url.URL) {
	// url.URL.EscapedPath() preserves percent-encoding from the raw input.
	raw := u.EscapedPath()
	if strings.Contains(raw, "%") {
		r.Fail(spec.IDPathNoPercent, "percent-encoding present")
	} else {
		r.Pass(spec.IDPathNoPercent, "")
	}

	if raw == "" {
		// Empty path is allowed (signing certs use the root SPIFFE ID).
		// The leaf-only requirement (§3.1 of X509-SVID) is enforced by the
		// caller, not here.
		r.Pass(spec.IDPathNoTrailingSlash, "")
		r.Pass(spec.IDPathNoEmptyOrDot, "")
		r.Pass(spec.IDPathSegmentCharset, "")
		return
	}

	if strings.HasSuffix(raw, "/") {
		r.Fail(spec.IDPathNoTrailingSlash, "")
	} else {
		r.Pass(spec.IDPathNoTrailingSlash, "")
	}

	segs := strings.Split(strings.TrimPrefix(raw, "/"), "/")
	badEmptyOrDot := false
	badCharset := ""
	for _, seg := range segs {
		if seg == "" || seg == "." || seg == ".." {
			badEmptyOrDot = true
		}
		if !isPathSegmentCharset(seg) && badCharset == "" {
			badCharset = seg
		}
	}
	if badEmptyOrDot {
		r.Fail(spec.IDPathNoEmptyOrDot, "")
	} else {
		r.Pass(spec.IDPathNoEmptyOrDot, "")
	}
	if badCharset != "" {
		r.Fail(spec.IDPathSegmentCharset, fmt.Sprintf("segment=%q", badCharset))
	} else {
		r.Pass(spec.IDPathSegmentCharset, "")
	}
}

func checkLength(r *report.Report, raw string) {
	if len(raw) > 2048 {
		r.Fail(spec.IDLengthLimit, fmt.Sprintf("len=%d", len(raw)))
	} else {
		r.Pass(spec.IDLengthLimit, "")
	}
}

func isTrustDomainCharset(s string) bool {
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '.' || c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}

func isPathSegmentCharset(s string) bool {
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '.' || c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}

// Parse is a lightweight accessor used by other checkers that just need the
// trust domain and path of a syntactically-valid SPIFFE ID. It does not
// perform any compliance checks beyond what url.Parse rejects.
func Parse(s string) (trustDomain, path string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return "", "", err
	}
	if !strings.EqualFold(u.Scheme, "spiffe") {
		return "", "", fmt.Errorf("scheme is %q, want spiffe", u.Scheme)
	}
	return u.Hostname(), u.EscapedPath(), nil
}
