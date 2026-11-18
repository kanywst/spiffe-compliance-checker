// Package workloadbundle checks the JWT and WIT bundles a Workload API server
// returns from FetchJWTBundles and FetchWITBundles (SPIFFE_Workload_API.md
// §6.2.2 and §7.2.2). Each is a plain RFC 7517 JWK Set for one trust domain.
package workloadbundle

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/kanywst/spiffe-compliance-checker/internal/bundle"
	"github.com/kanywst/spiffe-compliance-checker/internal/report"
	"github.com/kanywst/spiffe-compliance-checker/internal/spec"
)

// Profile selects which Workload API bundle is being checked.
type Profile string

const (
	JWT Profile = "jwt"
	WIT Profile = "wit"
)

// CheckFile reads a JWK Set from path and runs Check on it.
func CheckFile(r *report.Report, p Profile, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return Check(r, p, raw)
}

// Check evaluates the JWK Set in raw against the clauses of profile p.
func Check(r *report.Report, p Profile, raw []byte) error {
	if p != JWT && p != WIT {
		return fmt.Errorf("unknown profile %q, want jwt or wit", p)
	}
	set, err := bundle.DecodeJSON(raw)
	if err != nil {
		return fmt.Errorf("bundle is not valid JSON: %w", err)
	}
	if p == JWT {
		checkJWT(r, set)
	} else {
		checkWIT(r, set)
	}
	return nil
}

func checkJWT(r *report.Report, set map[string]any) {
	keys, ok := checkJWKSet(r, spec.WLJWTBundleJWKSet, set)
	if !ok {
		return
	}
	for i, jwk := range keys {
		if jwk == nil {
			continue
		}
		keyTag := fmt.Sprintf("keys[%d]", i)
		// "use" is optional here, unlike in a SPIFFE bundle.
		v, present := jwk["use"]
		if !present {
			r.Pass(spec.WLJWTBundleNoOtherUse, keyTag+": use absent")
			continue
		}
		use, ok := v.(string)
		switch {
		case !ok:
			r.Fail(spec.WLJWTBundleNoOtherUse, fmt.Sprintf("%s: use is %T, want string", keyTag, v))
		case use == "x509-svid", use == "wit-svid", use == "enc":
			r.Fail(spec.WLJWTBundleNoOtherUse, keyTag+": use="+use)
		default:
			r.Pass(spec.WLJWTBundleNoOtherUse, keyTag+": use="+use)
		}
	}
}

func checkWIT(r *report.Report, set map[string]any) {
	keys, ok := checkJWKSet(r, spec.WLWITBundleJWKSet, set)
	if !ok {
		return
	}
	seen := make(map[string]int, len(keys))
	var dupes []string
	for i, jwk := range keys {
		if jwk == nil {
			continue
		}
		keyTag := fmt.Sprintf("keys[%d]", i)
		v, present := jwk["kid"]
		if !present {
			r.Fail(spec.WLWITBundleKidPresent, keyTag+": kid absent")
			continue
		}
		kid, ok := v.(string)
		switch {
		case !ok:
			r.Fail(spec.WLWITBundleKidPresent, fmt.Sprintf("%s: kid is %T, want string", keyTag, v))
			continue
		case kid == "":
			r.Fail(spec.WLWITBundleKidPresent, keyTag+": kid is empty")
			continue
		}
		r.Pass(spec.WLWITBundleKidPresent, keyTag+": kid="+kid)
		seen[kid]++
		if seen[kid] == 2 {
			dupes = append(dupes, kid)
		}
	}
	if len(seen) == 0 {
		return
	}
	if len(dupes) > 0 {
		sort.Strings(dupes)
		r.Fail(spec.WLWITBundleKidUnique, "duplicate kid(s): "+strings.Join(dupes, ", "))
		return
	}
	r.Pass(spec.WLWITBundleKidUnique, plural(len(seen), "kid")+", all distinct")
}

// checkJWKSet asserts the RFC 7517 shape both profiles share. The returned
// slice keeps the original indexes; entries that are not objects are nil.
func checkJWKSet(r *report.Report, c spec.Clause, set map[string]any) ([]map[string]any, bool) {
	keysAny, ok := set["keys"]
	if !ok {
		r.Fail(c, `"keys" absent`)
		return nil, false
	}
	keys, ok := keysAny.([]any)
	if !ok {
		r.Fail(c, fmt.Sprintf(`"keys" is %T, want array`, keysAny))
		return nil, false
	}
	r.Pass(c, plural(len(keys), "key"))
	out := make([]map[string]any, len(keys))
	for i, k := range keys {
		keyTag := fmt.Sprintf("keys[%d]", i)
		jwk, ok := k.(map[string]any)
		if !ok {
			r.Fail(c, keyTag+" is not an object")
			continue
		}
		out[i] = jwk
		v, present := jwk["kty"]
		kty, isString := v.(string)
		switch {
		case !present:
			r.Fail(c, keyTag+": kty absent")
		case !isString:
			r.Fail(c, fmt.Sprintf("%s: kty is %T, want string", keyTag, v))
		case kty == "":
			r.Fail(c, keyTag+": kty is empty")
		default:
			r.Pass(c, keyTag+": kty="+kty)
		}
	}
	return out, true
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
