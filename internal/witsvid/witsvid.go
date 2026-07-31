// Package witsvid checks a WIT-SVID token against the MUST clauses of
// WIT-SVID.md — a JWS-signed JWT whose cnf claim binds the workload's public
// key to its SPIFFE ID. Signature verification and the proof of possession a
// WIT-SVID must be presented with are runtime concerns, intentionally out of
// scope; this is a structural conformance checker.
package witsvid

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/kanywst/spiffe-compliance-checker/internal/id"
	"github.com/kanywst/spiffe-compliance-checker/internal/jose"
	"github.com/kanywst/spiffe-compliance-checker/internal/report"
	"github.com/kanywst/spiffe-compliance-checker/internal/spec"
)

// allowedAlgs is the §2.3 table, reused by §3.2 for cnf.jwk.alg. It matches
// the JWT-SVID set today, but the two specs enumerate it independently, so the
// checkers keep independent copies.
var allowedAlgs = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"PS256": true, "PS384": true, "PS512": true,
	"ES256": true, "ES384": true, "ES512": true,
}

var permittedHeaders = map[string]bool{"alg": true, "kid": true, "typ": true}

// privateJWKParams are the JWK members carrying private or symmetric key
// material (RFC 7518 §6.2.2, §6.3.2, §6.4). RFC 7800, which §3.2 incorporates
// by reference, defines cnf.jwk as the public key, so any of these is leakage.
var privateJWKParams = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// clockSkewLeeway is the tolerance applied to exp and nbf. §3.4 permits
// "seconds to at most a couple of minutes".
const clockSkewLeeway = 30 * time.Second

// Check evaluates WIT-SVID.md against token and appends assertions to r.
func Check(r *report.Report, token string) {
	// §1: any structural problem the decoder reports violates this one clause.
	header, payload, err := jose.Decode(token)
	if err != nil {
		r.Fail(spec.WITCompactSerialization, err.Error())
		return
	}
	r.Pass(spec.WITCompactSerialization, "")

	checkHeader(r, header)
	checkClaims(r, payload)
}

// stringMember reads m[name] as a non-empty string, recording the matching
// failure against c when it is absent, the wrong type, or blank. kind is
// "header" or "claim" and only phrases the absence message. ok reports whether
// the caller should evaluate the value further; the caller records the Pass,
// since only it knows what detail to attach.
func stringMember(r *report.Report, m map[string]any, name, kind string, c spec.Clause) (string, bool) {
	v, present := m[name]
	if !present {
		r.Fail(c, fmt.Sprintf("%s %s absent", name, kind))
		return "", false
	}
	s, isString := v.(string)
	switch {
	case !isString:
		r.Fail(c, fmt.Sprintf("%s is %T, want string", name, v))
	case s == "":
		r.Fail(c, name+" is empty")
	default:
		return s, true
	}
	return "", false
}

func checkHeader(r *report.Report, h map[string]any) {
	// §2.1: kid MUST be present.
	if kid, ok := stringMember(r, h, "kid", "header", spec.WITKidPresent); ok {
		r.Pass(spec.WITKidPresent, "kid="+kid)
	}

	// §2.2: typ MUST be "wit+jwt". This is what keeps a WIT-SVID from being
	// mistaken for a JWT-SVID or an OIDC ID token.
	if typ, ok := stringMember(r, h, "typ", "header", spec.WITTypWitJWT); ok {
		if typ == "wit+jwt" {
			r.Pass(spec.WITTypWitJWT, "typ=wit+jwt")
		} else {
			r.Fail(spec.WITTypWitJWT, fmt.Sprintf("typ=%q", typ))
		}
	}

	// §2.3: alg MUST be one of the nine listed values.
	if alg, ok := stringMember(r, h, "alg", "header", spec.WITAlgWhitelist); ok {
		if allowedAlgs[alg] {
			r.Pass(spec.WITAlgWhitelist, "alg="+alg)
		} else {
			r.Fail(spec.WITAlgWhitelist, fmt.Sprintf("alg=%q", alg))
		}
	}

	// §2.4: implementations SHOULD NOT emit additional header parameters.
	var extra []string
	for k := range h {
		if !permittedHeaders[k] {
			extra = append(extra, k)
		}
	}
	if len(extra) == 0 {
		r.Pass(spec.WITHeaderNoAdditional, "")
		return
	}
	sort.Strings(extra)
	r.Fail(spec.WITHeaderNoAdditional, "additional header(s): "+strings.Join(extra, ", "))
}

func checkClaims(r *report.Report, p map[string]any) {
	checkSub(r, p)
	checkCnf(r, p)
	checkExp(r, p)
	checkNbf(r, p)
	checkIss(r, p)

	// §3.8: aud MUST NOT be included; scoping a WIT-SVID to a recipient is the
	// proof of possession's job, not the token's.
	if v, present := p["aud"]; present {
		r.Fail(spec.WITNoAud, fmt.Sprintf("aud=%v", v))
	} else {
		r.Pass(spec.WITNoAud, "")
	}
}

func checkSub(r *report.Report, p map[string]any) {
	// §3.1: sub MUST be present and set to the workload's SPIFFE ID.
	sub, ok := stringMember(r, p, "sub", "claim", spec.WITSubPresent)
	if !ok {
		return
	}
	r.Pass(spec.WITSubPresent, "sub="+sub)
	id.Check(r, sub)
}

func checkCnf(r *report.Report, p map[string]any) {
	// §3.2: cnf MUST be present, and its structure MUST follow RFC 7800 —
	// two obligations from one section, so two clauses.
	v, present := p["cnf"]
	if !present {
		r.Fail(spec.WITCnfPresent, "cnf claim absent")
		return
	}
	r.Pass(spec.WITCnfPresent, "")

	cnf, ok := v.(map[string]any)
	if !ok {
		r.Fail(spec.WITCnfJWK, fmt.Sprintf("cnf is %T, want object", v))
		return
	}
	jwkRaw, present := cnf["jwk"]
	if !present {
		r.Fail(spec.WITCnfJWK, "cnf.jwk absent")
		return
	}
	jwk, ok := jwkRaw.(map[string]any)
	if !ok {
		r.Fail(spec.WITCnfJWK, fmt.Sprintf("cnf.jwk is %T, want object", jwkRaw))
		return
	}
	r.Pass(spec.WITCnfJWK, "")

	var leaked []string
	for _, param := range privateJWKParams {
		if _, ok := jwk[param]; ok {
			leaked = append(leaked, param)
		}
	}
	if len(leaked) > 0 {
		sort.Strings(leaked)
		r.Fail(spec.WITCnfJWKPublic,
			"cnf.jwk carries private key parameter(s): "+strings.Join(leaked, ", "))
	} else {
		r.Pass(spec.WITCnfJWKPublic, "")
	}

	// §3.2: cnf.jwk.alg MUST be one of the nine listed values. Spelled out
	// rather than routed through stringMember so the detail names the full
	// path a reader would grep the token for.
	algRaw, present := jwk["alg"]
	if !present {
		r.Fail(spec.WITCnfJWKAlg, "cnf.jwk.alg absent")
		return
	}
	alg, ok := algRaw.(string)
	switch {
	case !ok:
		r.Fail(spec.WITCnfJWKAlg, fmt.Sprintf("cnf.jwk.alg is %T, want string", algRaw))
	case !allowedAlgs[alg]:
		r.Fail(spec.WITCnfJWKAlg, fmt.Sprintf("cnf.jwk.alg=%q", alg))
	default:
		r.Pass(spec.WITCnfJWKAlg, "cnf.jwk.alg="+alg)
	}
}

func checkExp(r *report.Report, p map[string]any) {
	// §3.4: exp MUST be present and MUST NOT be in the past.
	v, present := p["exp"]
	if !present {
		r.Fail(spec.WITExpPresent, "exp claim absent")
		return
	}
	r.Pass(spec.WITExpPresent, "")
	exp, err := jose.UnixClaim("exp", v)
	if err != nil {
		r.Fail(spec.WITExpNotInPast, fmt.Sprintf("exp invalid: %v", err))
		return
	}
	at := time.Unix(exp, 0)
	if time.Now().Add(-clockSkewLeeway).After(at) {
		r.Fail(spec.WITExpNotInPast,
			fmt.Sprintf("exp=%s (past)", at.UTC().Format(time.RFC3339)))
		return
	}
	r.Pass(spec.WITExpNotInPast, "exp="+at.UTC().Format(time.RFC3339))
}

func checkNbf(r *report.Report, p map[string]any) {
	// §3.5: nbf MAY be present; when it is, it MUST NOT be in the future.
	v, present := p["nbf"]
	if !present {
		return
	}
	nbf, err := jose.UnixClaim("nbf", v)
	if err != nil {
		r.Fail(spec.WITNbfNotInFuture, fmt.Sprintf("nbf invalid: %v", err))
		return
	}
	at := time.Unix(nbf, 0)
	if at.After(time.Now().Add(clockSkewLeeway)) {
		r.Fail(spec.WITNbfNotInFuture,
			fmt.Sprintf("nbf=%s (future)", at.UTC().Format(time.RFC3339)))
		return
	}
	r.Pass(spec.WITNbfNotInFuture, "nbf="+at.UTC().Format(time.RFC3339))
}

func checkIss(r *report.Report, p map[string]any) {
	// §3.7: iss MAY be present; when it is, it SHOULD NOT be a value
	// compatible with OpenID Connect Discovery.
	v, present := p["iss"]
	if !present {
		return
	}
	iss, ok := v.(string)
	if !ok {
		r.Fail(spec.WITIssNotOIDC, fmt.Sprintf("iss is %T, want string", v))
		return
	}
	if isOIDCDiscoverable(iss) {
		r.Fail(spec.WITIssNotOIDC,
			fmt.Sprintf("iss=%q is an https URL, so a relying party could resolve it "+
				"as an OIDC issuer and accept the token without proof of possession", iss))
		return
	}
	r.Pass(spec.WITIssNotOIDC, "iss="+iss)
}

// isOIDCDiscoverable reports whether s could serve as an OpenID Connect
// Discovery issuer: OIDC Discovery 1.0 §2 requires an https URL with no query
// or fragment. A spiffe:// ID or an opaque string cannot be resolved that way.
func isOIDCDiscoverable(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Scheme, "https") && u.Host != "" &&
		u.RawQuery == "" && u.Fragment == ""
}
