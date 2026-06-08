// Package bundle checks a SPIFFE Trust Bundle (a JWK Set with SPIFFE
// extensions) against the MUST clauses of SPIFFE_Trust_Domain_and_Bundle.md
// plus the per-SVID-spec requirements layered on top of bundle entries.
package bundle

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/kanywst/spiffe-compliance-checker/internal/report"
	"github.com/kanywst/spiffe-compliance-checker/internal/spec"
)

// CheckFile reads a JSON bundle from path and runs Check on it.
func CheckFile(r *report.Report, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return Check(r, raw)
}

// Check evaluates the bundle in raw against the SPIFFE spec. JSON numbers
// are decoded with UseNumber() so spiffe_sequence preserves its full integer
// width — the spec requires at least 64 bits of precision, but the default
// float64 path silently loses it past 2^53.
func Check(r *report.Report, raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var b map[string]any
	if err := dec.Decode(&b); err != nil {
		return fmt.Errorf("bundle is not valid JSON: %w", err)
	}

	keysAny, ok := b["keys"]
	if !ok {
		r.Fail(spec.BundleKeysPresent, `"keys" key absent`)
		return nil
	}
	r.Pass(spec.BundleKeysPresent, "")

	keys, ok := keysAny.([]any)
	if !ok {
		r.Fail(spec.BundleKeysPresent, fmt.Sprintf(`"keys" is %T, want array`, keysAny))
		return nil
	}

	checkSequence(r, b)
	checkRefreshHint(r, b)

	for i, k := range keys {
		jwk, ok := k.(map[string]any)
		if !ok {
			r.Fail(spec.BundleKeyKTYSet, fmt.Sprintf("keys[%d] is not an object", i))
			continue
		}
		checkJWK(r, i, jwk)
	}
	return nil
}

func checkSequence(r *report.Report, b map[string]any) {
	v, ok := b["spiffe_sequence"]
	if !ok {
		r.Fail(spec.BundleSequenceMonotonic, "spiffe_sequence absent")
		return
	}
	n, ok := v.(json.Number)
	if !ok {
		r.Fail(spec.BundleSequenceMonotonic,
			fmt.Sprintf("spiffe_sequence is %T, want integer", v))
		return
	}
	if !isIntegerNumber(n) {
		r.Fail(spec.BundleSequenceMonotonic,
			fmt.Sprintf("spiffe_sequence=%s is not integer", n))
		return
	}
	if isNegativeNumber(n) {
		// A monotonically-increasing version counter is not meaningfully
		// negative.
		r.Fail(spec.BundleSequenceMonotonic,
			fmt.Sprintf("spiffe_sequence=%s must be non-negative", n))
		return
	}
	r.Pass(spec.BundleSequenceMonotonic, fmt.Sprintf("spiffe_sequence=%s", n))
}

func checkRefreshHint(r *report.Report, b map[string]any) {
	v, ok := b["spiffe_refresh_hint"]
	if !ok {
		r.Fail(spec.BundleRefreshHintInteger, "spiffe_refresh_hint absent")
		return
	}
	n, ok := v.(json.Number)
	if !ok {
		r.Fail(spec.BundleRefreshHintInteger,
			fmt.Sprintf("spiffe_refresh_hint is %T, want integer", v))
		return
	}
	if !isIntegerNumber(n) {
		r.Fail(spec.BundleRefreshHintInteger,
			fmt.Sprintf("spiffe_refresh_hint=%s is not integer", n))
		return
	}
	if isNegativeNumber(n) {
		// A negative refresh interval has no physical meaning.
		r.Fail(spec.BundleRefreshHintInteger,
			fmt.Sprintf("spiffe_refresh_hint=%s must be non-negative", n))
		return
	}
	r.Pass(spec.BundleRefreshHintInteger, fmt.Sprintf("spiffe_refresh_hint=%ss", n))
}

// isIntegerNumber reports whether n is a plain JSON integer (no fractional
// component, no exponent notation).
func isIntegerNumber(n json.Number) bool {
	return !strings.ContainsAny(n.String(), ".eE")
}

// isNegativeNumber reports whether the JSON number is negative. json.Number
// preserves the source text so a leading "-" is sufficient evidence without
// having to fit into a fixed-width int type.
func isNegativeNumber(n json.Number) bool {
	return strings.HasPrefix(n.String(), "-")
}

// whitespaceStripper removes the whitespace characters commonly inserted by
// JWKS pretty-printers into x5c base64 blobs. Allocated once because Replacer
// avoids the per-call slice allocation of strings.Fields+Join.
var whitespaceStripper = strings.NewReplacer("\n", "", "\r", "", "\t", "", " ", "")

func checkJWK(r *report.Report, idx int, jwk map[string]any) {
	keyTag := fmt.Sprintf("keys[%d]", idx)

	switch v, ok := jwk["kty"]; {
	case !ok:
		r.Fail(spec.BundleKeyKTYSet, keyTag+": kty absent")
	default:
		kty, ok := v.(string)
		switch {
		case !ok:
			r.Fail(spec.BundleKeyKTYSet,
				fmt.Sprintf("%s: kty is %T, want string", keyTag, v))
		case kty == "":
			r.Fail(spec.BundleKeyKTYSet, keyTag+": kty is empty")
		default:
			r.Pass(spec.BundleKeyKTYSet, keyTag+": kty="+kty)
		}
	}

	useRaw, present := jwk["use"]
	if !present {
		r.Fail(spec.BundleKeyUseSet, keyTag+": use absent")
		return
	}
	use, ok := useRaw.(string)
	if !ok {
		r.Fail(spec.BundleKeyUseSet,
			fmt.Sprintf("%s: use is %T, want string", keyTag, useRaw))
		return
	}
	switch use {
	case "x509-svid":
		r.Pass(spec.BundleKeyUseSet, keyTag+": use=x509-svid")
		checkX509Entry(r, keyTag, jwk)
	case "jwt-svid":
		r.Pass(spec.BundleKeyUseSet, keyTag+": use=jwt-svid")
		checkJWTEntry(r, keyTag, jwk)
	case "":
		r.Fail(spec.BundleKeyUseSet, keyTag+": use is empty")
	default:
		r.Fail(spec.BundleKeyUseSet, keyTag+": use="+use)
	}
}

func checkX509Entry(r *report.Report, keyTag string, jwk map[string]any) {
	// X509-SVID.md §6.1: kid MUST NOT be set.
	if _, ok := jwk["kid"]; ok {
		r.Fail(spec.BundleX509NoKid, keyTag+": kid present")
	} else {
		r.Pass(spec.BundleX509NoKid, keyTag)
	}
	// X509-SVID.md §6.1: x5c MUST contain exactly one base64 DER cert.
	x5cRaw, ok := jwk["x5c"]
	if !ok {
		r.Fail(spec.BundleX509X5CPresent, keyTag+": x5c absent")
		return
	}
	x5c, ok := x5cRaw.([]any)
	if !ok {
		r.Fail(spec.BundleX509X5CPresent,
			fmt.Sprintf("%s: x5c is %T, want array", keyTag, x5cRaw))
		return
	}
	if len(x5c) != 1 {
		r.Fail(spec.BundleX509X5CPresent,
			fmt.Sprintf("%s: x5c has %d entries, want 1", keyTag, len(x5c)))
		return
	}
	// X509-SVID.md §6.1: x5c entry MUST be a base64-encoded DER X.509
	// certificate. Confirm both encoding and parseability.
	certStr, ok := x5c[0].(string)
	if !ok {
		r.Fail(spec.BundleX509X5CPresent,
			fmt.Sprintf("%s: x5c[0] is %T, want string", keyTag, x5c[0]))
		return
	}
	// Real-world JWKS often line-wrap or pretty-print x5c. base64.Std
	// does not tolerate whitespace, so strip it before decoding.
	normalized := whitespaceStripper.Replace(certStr)
	der, err := base64.StdEncoding.DecodeString(normalized)
	if err != nil {
		r.Fail(spec.BundleX509X5CPresent,
			fmt.Sprintf("%s: x5c[0] is not valid base64: %v", keyTag, err))
		return
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		r.Fail(spec.BundleX509X5CPresent,
			fmt.Sprintf("%s: x5c[0] is not a parseable X.509 cert: %v", keyTag, err))
		return
	}
	r.Pass(spec.BundleX509X5CPresent, keyTag)
}

func checkJWTEntry(r *report.Report, keyTag string, jwk map[string]any) {
	// JWT-SVID.md §6.1: kid MUST be set.
	v, present := jwk["kid"]
	if !present {
		r.Fail(spec.BundleJWTKidPresent, keyTag+": kid absent")
		return
	}
	kid, ok := v.(string)
	switch {
	case !ok:
		r.Fail(spec.BundleJWTKidPresent,
			fmt.Sprintf("%s: kid is %T, want string", keyTag, v))
	case kid == "":
		r.Fail(spec.BundleJWTKidPresent, keyTag+": kid is empty")
	default:
		r.Pass(spec.BundleJWTKidPresent, keyTag+": kid="+kid)
	}
}
