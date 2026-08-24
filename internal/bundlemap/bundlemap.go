// Package bundlemap checks a SPIFFE Bundle Map — the JSON structure defined in
// SPIFFE_Trust_Domain_and_Bundle.md §5 that carries several SPIFFE Bundles
// keyed by trust domain name. It owns only the map's own clauses; each embedded
// bundle is handed to internal/bundle, and what makes a trust domain name valid
// is deferred to internal/id, exactly as §5.1.1 defers to SPIFFE-ID.md §2.
package bundlemap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/kanywst/spiffe-compliance-checker/internal/bundle"
	"github.com/kanywst/spiffe-compliance-checker/internal/id"
	"github.com/kanywst/spiffe-compliance-checker/internal/report"
	"github.com/kanywst/spiffe-compliance-checker/internal/spec"
)

// CheckFile reads a JSON bundle map from path and runs Check on it.
func CheckFile(r *report.Report, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return Check(r, raw)
}

// Check evaluates the bundle map in raw against the SPIFFE spec.
func Check(r *report.Report, raw []byte) error {
	m, err := bundle.DecodeJSON(raw)
	if err != nil {
		return fmt.Errorf("bundle map is not valid JSON: %w", err)
	}
	// encoding/json collapses duplicate object keys onto the last one, so the
	// decoded map alone cannot answer §5.1.1's "consumers MUST reject duplicate
	// trust domain name keys". Re-walk the raw bytes at token level to recover
	// the names as written, duplicates included and in document order.
	names, err := trustDomainNames(raw)
	if err != nil {
		return fmt.Errorf("bundle map is not valid JSON: %w", err)
	}

	tdAny, ok := m["trust_domains"]
	if !ok {
		// Nothing left to check: the map carries no bundles.
		r.Fail(spec.BundleMapTrustDomainsPresent, `"trust_domains" key absent`)
		return nil
	}
	td, ok := tdAny.(map[string]any)
	if !ok {
		r.Fail(spec.BundleMapTrustDomainsPresent,
			fmt.Sprintf(`"trust_domains" is %T, want object`, tdAny))
		return nil
	}
	noun := "trust domains"
	if len(td) == 1 {
		noun = "trust domain"
	}
	r.Pass(spec.BundleMapTrustDomainsPresent, fmt.Sprintf("%d %s", len(td), noun))

	checkUniqueness(r, names)

	// Iterate in document order rather than over the decoded map, so the report
	// reads top-to-bottom like the file. A duplicated name is checked once,
	// against the value encoding/json kept.
	for _, name := range distinct(names) {
		tag := fmt.Sprintf("trust_domains[%q]", name)
		id.CheckTrustDomain(r, tag, name)

		entry, ok := td[name].(map[string]any)
		if !ok {
			r.Fail(spec.BundleMapEntryIsBundle,
				fmt.Sprintf("%s is %T, want object", tag, td[name]))
			continue
		}
		r.Pass(spec.BundleMapEntryIsBundle, tag)
		bundle.CheckMapMember(r, tag, entry)
	}
	return nil
}

// checkUniqueness asserts §5.1.1's uniqueness requirement over the names as
// they appear in the document. An empty map is explicitly allowed, so it gets
// no assertion rather than a vacuous pass.
func checkUniqueness(r *report.Report, names []string) {
	if len(names) == 0 {
		return
	}
	seen := make(map[string]int, len(names))
	var dupes []string
	for _, n := range names {
		seen[n]++
		if seen[n] == 2 {
			dupes = append(dupes, n)
		}
	}
	if len(dupes) == 0 {
		noun := "names"
		if len(names) == 1 {
			noun = "name"
		}
		r.Pass(spec.BundleMapTrustDomainsUnique,
			fmt.Sprintf("%d trust domain %s, all distinct", len(names), noun))
		return
	}
	sort.Strings(dupes)
	r.Fail(spec.BundleMapTrustDomainsUnique,
		"duplicate trust domain name(s): "+strings.Join(dupes, ", "))
}

// distinct returns names with duplicates removed, preserving first-seen order.
func distinct(names []string) []string {
	seen := make(map[string]bool, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// trustDomainNames walks raw at the JSON token level and returns the keys of
// its "trust_domains" object in document order, duplicates included. Returns
// nil when the document is not an object or has no "trust_domains" key.
func trustDomainNames(raw []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, nil
	}
	var names []string
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := keyTok.(string)
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return nil, err
		}
		if key != "trust_domains" {
			continue
		}
		// A duplicated "trust_domains" key itself collapses onto the last
		// occurrence when decoded, so mirror that and keep scanning.
		names, err = objectKeys(val)
		if err != nil {
			return nil, err
		}
	}
	return names, nil
}

// objectKeys returns the keys of the JSON object in raw, in document order and
// with duplicates preserved. A non-object value yields no keys.
func objectKeys(raw []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, nil
	}
	var keys []string
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := keyTok.(string)
		keys = append(keys, key)
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return nil, err
		}
	}
	return keys, nil
}
