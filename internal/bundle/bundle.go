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
	"sort"
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

// Check evaluates the bundle in raw against the SPIFFE spec.
func Check(r *report.Report, raw []byte) error {
	b, err := DecodeJSON(raw)
	if err != nil {
		return fmt.Errorf("bundle is not valid JSON: %w", err)
	}
	CheckObject(r, "", b)
	return nil
}

// DecodeJSON decodes a SPIFFE bundle document into a generic object. Numbers
// are decoded with UseNumber() so spiffe_sequence preserves its full integer
// width — the spec requires at least 64 bits of precision, but the default
// float64 path silently loses it past 2^53. Exported because a SPIFFE Bundle
// Map embeds bundles verbatim and needs the same guarantee.
func DecodeJSON(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var b map[string]any
	if err := dec.Decode(&b); err != nil {
		return nil, err
	}
	return b, nil
}

// CheckObject evaluates an already-decoded standalone bundle. tag, when
// non-empty, prefixes every detail so a caller checking several bundles can say
// which one an assertion came from.
func CheckObject(r *report.Report, tag string, b map[string]any) {
	check(r, tag, b, false)
}

// CheckMapMember evaluates a bundle embedded in a SPIFFE Bundle Map. §5.1.1
// inverts the refresh-hint expectation — the hint applies to the map as a
// whole, so a bundle inside one SHOULD omit it — and every other clause is
// unchanged.
func CheckMapMember(r *report.Report, tag string, b map[string]any) {
	check(r, tag, b, true)
}

func check(r *report.Report, tag string, b map[string]any, inMap bool) {
	keysAny, ok := b["keys"]
	if !ok {
		r.Fail(spec.BundleKeysPresent, annotate(tag, `"keys" key absent`))
		return
	}
	r.Pass(spec.BundleKeysPresent, annotate(tag, ""))

	keys, ok := keysAny.([]any)
	if !ok {
		r.Fail(spec.BundleKeysPresent,
			annotate(tag, fmt.Sprintf(`"keys" is %T, want array`, keysAny)))
		return
	}

	checkSequence(r, tag, b)
	if inMap {
		checkRefreshHintOmitted(r, tag, b)
	} else {
		checkRefreshHint(r, tag, b)
	}

	// Token-signing entries (jwt-svid, wit-svid) carry a kid that must be
	// unique bundle-wide, so collect them as we go and assert once at the end.
	kids := make([]string, 0, len(keys))
	for i, k := range keys {
		keyTag := qualify(tag, fmt.Sprintf("keys[%d]", i))
		jwk, ok := k.(map[string]any)
		if !ok {
			r.Fail(spec.BundleKeyKTYSet, keyTag+" is not an object")
			continue
		}
		if kid := checkJWK(r, keyTag, jwk); kid != "" {
			kids = append(kids, kid)
		}
	}
	checkKIDUniqueness(r, tag, kids)
}

// qualify prefixes a field path with the bundle's tag, so "keys[0]" reads as
// `trust_domains["example.com"].keys[0]` inside a SPIFFE Bundle Map and stays
// "keys[0]" for a standalone bundle.
func qualify(tag, field string) string {
	if tag == "" {
		return field
	}
	return tag + "." + field
}

// annotate prefixes a free-text observation with the bundle's tag, collapsing
// to whichever half is non-empty so an untagged bundle renders exactly as it
// did before bundle maps existed.
func annotate(tag, msg string) string {
	switch {
	case tag == "":
		return msg
	case msg == "":
		return tag
	default:
		return tag + ": " + msg
	}
}

// checkKIDUniqueness enforces WIT-SVID.md §6.1. x509-svid entries carry no kid
// at all (X509-SVID.md §6.1), so they cannot collide and are not counted here.
// Uniqueness is scoped to one bundle: inside a map, each trust domain's bundle
// gets its own assertion.
func checkKIDUniqueness(r *report.Report, tag string, kids []string) {
	if len(kids) == 0 {
		return
	}
	seen := make(map[string]int, len(kids))
	var dupes []string
	for _, kid := range kids {
		seen[kid]++
		if seen[kid] == 2 {
			dupes = append(dupes, kid)
		}
	}
	if len(dupes) == 0 {
		noun := "entries"
		if len(kids) == 1 {
			noun = "entry"
		}
		r.Pass(spec.BundleKIDUnique,
			annotate(tag, fmt.Sprintf("%d keyed %s, all kids distinct", len(kids), noun)))
		return
	}
	sort.Strings(dupes)
	r.Fail(spec.BundleKIDUnique,
		annotate(tag, "duplicate kid(s): "+strings.Join(dupes, ", ")))
}

func checkSequence(r *report.Report, tag string, b map[string]any) {
	v, ok := b["spiffe_sequence"]
	if !ok {
		r.Fail(spec.BundleSequenceMonotonic, annotate(tag, "spiffe_sequence absent"))
		return
	}
	n, ok := v.(json.Number)
	if !ok {
		r.Fail(spec.BundleSequenceMonotonic,
			annotate(tag, fmt.Sprintf("spiffe_sequence is %T, want integer", v)))
		return
	}
	if !isIntegerNumber(n) {
		r.Fail(spec.BundleSequenceMonotonic,
			annotate(tag, fmt.Sprintf("spiffe_sequence=%s is not integer", n)))
		return
	}
	if isNegativeNumber(n) {
		// A monotonically-increasing version counter is not meaningfully
		// negative.
		r.Fail(spec.BundleSequenceMonotonic,
			annotate(tag, fmt.Sprintf("spiffe_sequence=%s must be non-negative", n)))
		return
	}
	r.Pass(spec.BundleSequenceMonotonic, annotate(tag, fmt.Sprintf("spiffe_sequence=%s", n)))
}

func checkRefreshHint(r *report.Report, tag string, b map[string]any) {
	v, ok := b["spiffe_refresh_hint"]
	if !ok {
		r.Fail(spec.BundleRefreshHintInteger, annotate(tag, "spiffe_refresh_hint absent"))
		return
	}
	n, ok := v.(json.Number)
	if !ok {
		r.Fail(spec.BundleRefreshHintInteger,
			annotate(tag, fmt.Sprintf("spiffe_refresh_hint is %T, want integer", v)))
		return
	}
	if !isIntegerNumber(n) {
		r.Fail(spec.BundleRefreshHintInteger,
			annotate(tag, fmt.Sprintf("spiffe_refresh_hint=%s is not integer", n)))
		return
	}
	if isNegativeNumber(n) {
		// A negative refresh interval has no physical meaning.
		r.Fail(spec.BundleRefreshHintInteger,
			annotate(tag, fmt.Sprintf("spiffe_refresh_hint=%s must be non-negative", n)))
		return
	}
	r.Pass(spec.BundleRefreshHintInteger, annotate(tag, fmt.Sprintf("spiffe_refresh_hint=%ss", n)))
}

// checkRefreshHintOmitted replaces checkRefreshHint for bundles inside a SPIFFE
// Bundle Map. §5.1.1 tells producers to leave the hint out there and consumers
// to ignore it if present, so the value is not worth type-checking — only its
// absence is asserted.
func checkRefreshHintOmitted(r *report.Report, tag string, b map[string]any) {
	if _, ok := b["spiffe_refresh_hint"]; ok {
		r.Fail(spec.BundleMapNoRefreshHint, annotate(tag, "spiffe_refresh_hint present"))
		return
	}
	r.Pass(spec.BundleMapNoRefreshHint, annotate(tag, ""))
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

// checkJWK evaluates one JWK entry and returns its kid, or "" when the entry
// has no valid kid to contribute to the bundle-wide uniqueness check. keyTag
// is the entry's already-qualified path, e.g. "keys[0]".
func checkJWK(r *report.Report, keyTag string, jwk map[string]any) string {
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

	// §4.2.2 carries two obligations: "use" MUST be set, and its value SHOULD
	// name a known SVID type. See the clause table for why the second is only
	// a SHOULD.
	useRaw, present := jwk["use"]
	if !present {
		r.Fail(spec.BundleKeyUseSet, keyTag+": use absent")
		return ""
	}
	use, ok := useRaw.(string)
	if !ok {
		r.Fail(spec.BundleKeyUseSet,
			fmt.Sprintf("%s: use is %T, want string", keyTag, useRaw))
		return ""
	}
	if use == "" {
		r.Fail(spec.BundleKeyUseSet, keyTag+": use is empty")
		return ""
	}
	r.Pass(spec.BundleKeyUseSet, keyTag+": use="+use)

	// The value itself is already reported on the clause above, so these
	// assertions only carry the entry index.
	switch use {
	case "x509-svid":
		r.Pass(spec.BundleKeyUseKnown, keyTag)
		checkX509Entry(r, keyTag, jwk)
		return ""
	case "jwt-svid":
		r.Pass(spec.BundleKeyUseKnown, keyTag)
		return checkKidSet(r, keyTag, jwk, spec.BundleJWTKidPresent)
	case "wit-svid":
		r.Pass(spec.BundleKeyUseKnown, keyTag)
		return checkKidSet(r, keyTag, jwk, spec.BundleWITKidPresent)
	default:
		r.Fail(spec.BundleKeyUseKnown, keyTag+": use="+use)
		return ""
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
	// §6.1 mandates base64-encoded DER, not PEM. Pasting PEM armor is a common
	// mistake that would otherwise surface as an opaque base64 error, so detect
	// it and say so plainly.
	if strings.Contains(certStr, "-----BEGIN") {
		r.Fail(spec.BundleX509X5CPresent,
			keyTag+": x5c[0] is PEM; it MUST be base64-encoded DER, without the PEM armor")
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
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		r.Fail(spec.BundleX509X5CPresent,
			fmt.Sprintf("%s: x5c[0] is not a parseable X.509 cert: %v", keyTag, err))
		return
	}
	r.Pass(spec.BundleX509X5CPresent, keyTag)

	// X509-SVID.md §6.1: "the certificate SHOULD be self-signed." A bundle CA
	// is a trust anchor, so a non-self-signed entry is suspicious though not
	// strictly forbidden (hence SHOULD/WARN).
	if isSelfSigned(cert) {
		r.Pass(spec.BundleX509SelfSigned, keyTag)
	} else {
		r.Fail(spec.BundleX509SelfSigned,
			keyTag+": x5c[0] is not self-signed (issuer != subject or signature not self-verifiable)")
	}
}

// isSelfSigned reports whether cert is self-signed: its issuer and subject
// match and its signature verifies against its own public key.
func isSelfSigned(cert *x509.Certificate) bool {
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil
}

// checkKidSet enforces the "kid MUST be set" requirement that JWT-SVID.md §6.1
// and WIT-SVID.md §6.1 each place on their own entries; the caller supplies the
// clause to cite. The kid is returned to feed the uniqueness assertion.
func checkKidSet(r *report.Report, keyTag string, jwk map[string]any, c spec.Clause) string {
	v, present := jwk["kid"]
	if !present {
		r.Fail(c, keyTag+": kid absent")
		return ""
	}
	kid, ok := v.(string)
	switch {
	case !ok:
		r.Fail(c, fmt.Sprintf("%s: kid is %T, want string", keyTag, v))
	case kid == "":
		r.Fail(c, keyTag+": kid is empty")
	default:
		r.Pass(c, keyTag+": kid="+kid)
		return kid
	}
	return ""
}
