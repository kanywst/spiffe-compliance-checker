// Package witsvid checks a WIT-SVID token against the MUST clauses of
// WIT-SVID.md. A WIT-SVID is a SPIFFE sub-profile of the IETF WIMSE Workload
// Identity Token: a JWS-signed JWT whose cnf claim binds the workload's public
// key to its SPIFFE ID. Signature verification and the proof of possession
// that a WIT-SVID must always be presented with are runtime concerns and
// deliberately out of scope; this checks the shape of the token only.
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

// allowedAlgs is the table from §2.3, reused by §3.2 for cnf.jwk.alg. It
// happens to match the JWT-SVID set today, but the two specs enumerate it
// independently, so the checkers keep independent copies.
var allowedAlgs = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"PS256": true, "PS384": true, "PS512": true,
	"ES256": true, "ES384": true, "ES512": true,
}

// permittedHeaders is the set §2.4 describes; anything else is an "additional
// header parameter" that implementations SHOULD NOT emit.
var permittedHeaders = map[string]bool{"alg": true, "kid": true, "typ": true}

// privateJWKParams are the JWK members that carry private or symmetric key
// material (RFC 7518 §6.2.2, §6.3.2, §6.4). RFC 7800 — which WIT-SVID.md §3.2
// incorporates by reference — defines cnf.jwk as holding the *public* key, so
// any of these appearing in a token is key leakage.
var privateJWKParams = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// clockSkewLeeway is the tolerance applied to exp and nbf. §3.4 permits
// "seconds to at most a couple of minutes" for clock skew; 30s is the same
// allowance the JWT-SVID checker uses.
const clockSkewLeeway = 30 * time.Second

// Check evaluates WIT-SVID.md against token and appends assertions to r.
func Check(r *report.Report, token string) {
	// §1: a WIT-SVID is a JWT using JWS Compact Serialization. Any structural
	// problem the decoder reports violates that clause.
	header, payload, err := jose.Decode(token)
	if err != nil {
		r.Fail(spec.WITCompactSerialization, err.Error())
		return
	}
	r.Pass(spec.WITCompactSerialization, "")

	checkHeader(r, header)
	checkClaims(r, payload)
}

func checkHeader(r *report.Report, h map[string]any) {
	// §2.1: kid MUST be present, and is a case-sensitive string.
	switch v, present := h["kid"]; {
	case !present:
		r.Fail(spec.WITKidPresent, "kid header absent")
	default:
		kid, ok := v.(string)
		switch {
		case !ok:
			r.Fail(spec.WITKidPresent, fmt.Sprintf("kid is %T, want string", v))
		case kid == "":
			r.Fail(spec.WITKidPresent, "kid is empty")
		default:
			r.Pass(spec.WITKidPresent, "kid="+kid)
		}
	}

	// §2.2: typ MUST be present and set to "wit+jwt". This is what keeps a
	// WIT-SVID from being mistaken for a JWT-SVID or an OIDC ID token.
	switch v, present := h["typ"]; {
	case !present:
		r.Fail(spec.WITTypWitJWT, "typ header absent")
	default:
		typ, ok := v.(string)
		switch {
		case !ok:
			r.Fail(spec.WITTypWitJWT, fmt.Sprintf("typ is %T, want string", v))
		case typ != "wit+jwt":
			r.Fail(spec.WITTypWitJWT, fmt.Sprintf("typ=%q", typ))
		default:
			r.Pass(spec.WITTypWitJWT, "typ=wit+jwt")
		}
	}

	// §2.3: alg MUST be present and one of the nine listed values.
	switch v, present := h["alg"]; {
	case !present:
		r.Fail(spec.WITAlgWhitelist, "alg header absent")
	default:
		alg, ok := v.(string)
		switch {
		case !ok:
			r.Fail(spec.WITAlgWhitelist, fmt.Sprintf("alg is %T, want string", v))
		case !allowedAlgs[alg]:
			r.Fail(spec.WITAlgWhitelist, fmt.Sprintf("alg=%q", alg))
		default:
			r.Pass(spec.WITAlgWhitelist, "alg="+alg)
		}
	}

	// §2.4: implementations SHOULD NOT emit additional header parameters.
	var extra []string
	for k := range h {
		if !permittedHeaders[k] {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		r.Fail(spec.WITHeaderNoAdditional,
			"additional header(s): "+strings.Join(extra, ", "))
	} else {
		r.Pass(spec.WITHeaderNoAdditional, "")
	}
}

func checkClaims(r *report.Report, p map[string]any) {
	checkSub(r, p)
	checkCnf(r, p)
	checkExp(r, p)
	checkNbf(r, p)
	checkIss(r, p)

	// §3.8: aud MUST NOT be included. A WIT-SVID is not a bearer token, so
	// scoping it to a recipient is the proof of possession's job.
	if v, present := p["aud"]; present {
		r.Fail(spec.WITNoAud, fmt.Sprintf("aud=%v", v))
	} else {
		r.Pass(spec.WITNoAud, "")
	}
}

func checkSub(r *report.Report, p map[string]any) {
	// §3.1: sub MUST be present and set to the workload's SPIFFE ID.
	v, present := p["sub"]
	if !present {
		r.Fail(spec.WITSubPresent, "sub claim absent")
		return
	}
	sub, ok := v.(string)
	switch {
	case !ok:
		r.Fail(spec.WITSubPresent, fmt.Sprintf("sub claim is %T, want string", v))
	case sub == "":
		r.Fail(spec.WITSubPresent, "sub claim is empty")
	default:
		r.Pass(spec.WITSubPresent, "sub="+sub)
		// Propagate the SPIFFE-ID clauses through the sub value.
		id.Check(r, sub)
	}
}

func checkCnf(r *report.Report, p map[string]any) {
	// §3.2: cnf MUST be present.
	v, present := p["cnf"]
	if !present {
		r.Fail(spec.WITCnfPresent, "cnf claim absent")
		return
	}
	cnf, ok := v.(map[string]any)
	if !ok {
		r.Fail(spec.WITCnfPresent, fmt.Sprintf("cnf is %T, want object", v))
		return
	}
	r.Pass(spec.WITCnfPresent, "")

	// §3.2 via RFC 7800: the confirmation is expressed as a "jwk" member.
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

	// RFC 7800 defines cnf.jwk as the public key. Private or symmetric
	// material here would be exfiltrated to every validator that sees the
	// token, so check before anything else touches the key.
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

	// §3.2: cnf.jwk.alg MUST be one of the nine listed values.
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
// Discovery issuer. OIDC Discovery 1.0 §2 requires the issuer identifier to be
// an https URL with no query or fragment, which is exactly the shape §3.7 warns
// against; a spiffe:// ID or an opaque string cannot be resolved that way.
func isOIDCDiscoverable(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Scheme, "https") && u.Host != "" &&
		u.RawQuery == "" && u.Fragment == ""
}
