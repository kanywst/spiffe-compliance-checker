// Package jwtsvid checks a JWT-SVID token against the MUST clauses of
// JWT-SVID.md. Signature validation against a Trust Bundle is intentionally
// out of scope; this is a structural conformance checker, not a verifier.
package jwtsvid

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/0-draft/spiffe-compliance-checker/internal/id"
	"github.com/0-draft/spiffe-compliance-checker/internal/report"
	"github.com/0-draft/spiffe-compliance-checker/internal/spec"
)

var allowedAlgs = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"PS256": true, "PS384": true, "PS512": true,
	"ES256": true, "ES384": true, "ES512": true,
}

// Check evaluates JWT-SVID.md against token and appends assertions to r.
func Check(r *report.Report, token string) {
	token = strings.TrimSpace(token)
	// §1: JWT-SVID MUST use JWS Compact Serialization. Compact is exactly
	// three Base64URL parts joined by ".". JWS JSON Serialization is a JSON
	// object, which would start with "{" and contain no dots in the same
	// shape.
	parts := strings.Split(token, ".")
	if len(parts) != 3 || strings.HasPrefix(token, "{") {
		r.Fail(spec.JWTCompactSerialization,
			fmt.Sprintf("expected 3 dot-separated parts, got %d", len(parts)))
		return
	}
	r.Pass(spec.JWTCompactSerialization, "")

	header, err := decodePart(parts[0])
	if err != nil {
		r.Fail(spec.JWTCompactSerialization, fmt.Sprintf("header decode: %v", err))
		return
	}
	payload, err := decodePart(parts[1])
	if err != nil {
		r.Fail(spec.JWTCompactSerialization, fmt.Sprintf("payload decode: %v", err))
		return
	}

	checkHeader(r, header)
	checkClaims(r, payload)
}

func decodePart(s string) (map[string]any, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		// Some encoders include padding; tolerate that case.
		raw, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func checkHeader(r *report.Report, h map[string]any) {
	// §2.1: alg MUST be one of the whitelisted values.
	alg, _ := h["alg"].(string)
	if !allowedAlgs[alg] {
		r.Fail(spec.JWTAlgWhitelist, fmt.Sprintf("alg=%q", alg))
	} else {
		r.Pass(spec.JWTAlgWhitelist, fmt.Sprintf("alg=%s", alg))
	}

	// §2.3: typ, if set, MUST be JWT or JOSE.
	if v, ok := h["typ"]; ok {
		t, _ := v.(string)
		if t != "JWT" && t != "JOSE" {
			r.Fail(spec.JWTTypValue, fmt.Sprintf("typ=%q", t))
		} else {
			r.Pass(spec.JWTTypValue, fmt.Sprintf("typ=%s", t))
		}
	}
}

func checkClaims(r *report.Report, p map[string]any) {
	// §3.1: sub MUST be set to a SPIFFE ID.
	sub, _ := p["sub"].(string)
	if sub == "" {
		r.Fail(spec.JWTSubPresent, "sub claim absent")
	} else {
		r.Pass(spec.JWTSubPresent, fmt.Sprintf("sub=%s", sub))
		// Run the SPIFFE-ID checks against the sub value so SPIFFE-ID MUST
		// clauses are propagated.
		id.Check(r, sub)
	}

	// §3.2: aud MUST be present with one or more values.
	auds, present := extractAud(p)
	switch {
	case !present:
		r.Fail(spec.JWTAudPresent, "aud claim absent")
	case len(auds) == 0:
		r.Fail(spec.JWTAudPresent, "aud claim empty")
	default:
		r.Pass(spec.JWTAudPresent, fmt.Sprintf("aud=%v", auds))
	}

	// §3.2 (SHOULD): single audience recommended.
	if len(auds) > 1 {
		r.Fail(spec.JWTAudSingleRecommended, fmt.Sprintf("aud has %d values", len(auds)))
	} else if len(auds) == 1 {
		r.Pass(spec.JWTAudSingleRecommended, "")
	}

	// §3.3: exp MUST be set; App.A: MUST NOT be in the past (small leeway).
	expRaw, ok := p["exp"]
	if !ok {
		r.Fail(spec.JWTExpPresent, "exp claim absent")
		return
	}
	r.Pass(spec.JWTExpPresent, "")
	exp, err := asUnix(expRaw)
	if err != nil {
		r.Fail(spec.JWTExpNotInPast, fmt.Sprintf("exp invalid: %v", err))
		return
	}
	leeway := 30 * time.Second
	if time.Now().Add(-leeway).After(time.Unix(exp, 0)) {
		r.Fail(spec.JWTExpNotInPast,
			fmt.Sprintf("exp=%s (past)", time.Unix(exp, 0).UTC().Format(time.RFC3339)))
	} else {
		r.Pass(spec.JWTExpNotInPast,
			fmt.Sprintf("exp=%s", time.Unix(exp, 0).UTC().Format(time.RFC3339)))
	}
}

func extractAud(p map[string]any) (values []string, present bool) {
	v, ok := p["aud"]
	if !ok {
		return nil, false
	}
	switch a := v.(type) {
	case string:
		if a == "" {
			return nil, true
		}
		return []string{a}, true
	case []any:
		out := make([]string, 0, len(a))
		for _, x := range a {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out, true
	}
	return nil, true
}

func asUnix(v any) (int64, error) {
	switch x := v.(type) {
	case float64:
		return int64(x), nil
	case int64:
		return x, nil
	case int:
		return int64(x), nil
	default:
		return 0, fmt.Errorf("exp must be numeric, got %T", v)
	}
}
