// Package bundle checks a SPIFFE Trust Bundle (a JWK Set with SPIFFE
// extensions) against the MUST clauses of SPIFFE_Trust_Domain_and_Bundle.md
// plus the per-SVID-spec requirements layered on top of bundle entries.
package bundle

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/0-draft/spiffe-compliance-checker/internal/report"
	"github.com/0-draft/spiffe-compliance-checker/internal/spec"
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
	var b map[string]any
	if err := json.Unmarshal(raw, &b); err != nil {
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
	// JSON numbers decode to float64; SPIFFE spec requires integer semantics
	// with at least 64-bit precision.
	switch n := v.(type) {
	case float64:
		if n != float64(int64(n)) {
			r.Fail(spec.BundleSequenceMonotonic, fmt.Sprintf("spiffe_sequence=%v is not integer", n))
			return
		}
		r.Pass(spec.BundleSequenceMonotonic, fmt.Sprintf("spiffe_sequence=%d", int64(n)))
	default:
		r.Fail(spec.BundleSequenceMonotonic, fmt.Sprintf("spiffe_sequence is %T, want integer", v))
	}
}

func checkRefreshHint(r *report.Report, b map[string]any) {
	v, ok := b["spiffe_refresh_hint"]
	if !ok {
		r.Fail(spec.BundleRefreshHintInteger, "spiffe_refresh_hint absent")
		return
	}
	switch n := v.(type) {
	case float64:
		if n != float64(int64(n)) {
			r.Fail(spec.BundleRefreshHintInteger,
				fmt.Sprintf("spiffe_refresh_hint=%v is not integer", n))
			return
		}
		r.Pass(spec.BundleRefreshHintInteger,
			fmt.Sprintf("spiffe_refresh_hint=%ds", int64(n)))
	default:
		r.Fail(spec.BundleRefreshHintInteger,
			fmt.Sprintf("spiffe_refresh_hint is %T, want integer", v))
	}
}

func checkJWK(r *report.Report, idx int, jwk map[string]any) {
	keyTag := fmt.Sprintf("keys[%d]", idx)

	kty, _ := jwk["kty"].(string)
	if kty == "" {
		r.Fail(spec.BundleKeyKTYSet, keyTag+": kty absent")
	} else {
		r.Pass(spec.BundleKeyKTYSet, keyTag+": kty="+kty)
	}

	use, _ := jwk["use"].(string)
	switch use {
	case "x509-svid":
		r.Pass(spec.BundleKeyUseSet, keyTag+": use=x509-svid")
		checkX509Entry(r, keyTag, jwk)
	case "jwt-svid":
		r.Pass(spec.BundleKeyUseSet, keyTag+": use=jwt-svid")
		checkJWTEntry(r, keyTag, jwk)
	case "":
		r.Fail(spec.BundleKeyUseSet, keyTag+": use absent")
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
	r.Pass(spec.BundleX509X5CPresent, keyTag)
}

func checkJWTEntry(r *report.Report, keyTag string, jwk map[string]any) {
	// JWT-SVID.md §6.1: kid MUST be set.
	if kid, _ := jwk["kid"].(string); kid == "" {
		r.Fail(spec.BundleJWTKidPresent, keyTag+": kid absent or empty")
	} else {
		r.Pass(spec.BundleJWTKidPresent, keyTag+": kid="+kid)
	}
}
