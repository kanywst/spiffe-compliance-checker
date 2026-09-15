// Package federation checks a SPIFFE bundle endpoint configuration — the set
// of parameters SPIFFE_Federation.md §5.1 says a client MUST hold before it
// can retrieve a foreign trust bundle — against the clauses of §5.
//
// SPIFFE_Federation.md defines no serialization for this configuration, only
// the parameters themselves, so Config is the artifact: the checker validates
// the parameter set an operator supplies, not a file format this project would
// have had to invent. Everything the spec says about what happens once the
// client connects — TLS, certificate validation, HTTP GETs, redirects — is
// runtime and stays out of scope.
package federation

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/kanywst/spiffe-compliance-checker/internal/bundle"
	"github.com/kanywst/spiffe-compliance-checker/internal/id"
	"github.com/kanywst/spiffe-compliance-checker/internal/report"
	"github.com/kanywst/spiffe-compliance-checker/internal/spec"
)

// Endpoint profile types defined by SPIFFE_Federation.md §5.2.
const (
	ProfileWeb    = "https_web"
	ProfileSPIFFE = "https_spiffe"
)

// Config is a bundle endpoint configuration. URL, Profile and TrustDomain are
// the three parameters §5.1 requires of every profile; EndpointID and
// BundlePath are the additions §5.2.2.2 defines for https_spiffe.
type Config struct {
	URL         string
	Profile     string
	TrustDomain string
	EndpointID  string
	BundlePath  string
}

// Check evaluates cfg against SPIFFE_Federation.md §5 and appends the
// assertions to r. It returns an error only when a referenced bootstrap bundle
// cannot be read or parsed, which leaves that part of the configuration with no
// input to check.
func Check(r *report.Report, cfg Config) error {
	checkRequired(r, cfg)
	checkProfile(r, cfg)
	checkURL(r, cfg)
	return checkProfileParams(r, cfg)
}

// checkRequired covers §5.1's three mandatory parameters. The trust domain
// name gets the full SPIFFE-ID.md §2.1/§2.3 sweep on top: §5.1 calls it "the
// trust domain name", and a name that is not a valid trust domain cannot
// address one.
func checkRequired(r *report.Report, cfg Config) {
	if cfg.URL == "" {
		r.Fail(spec.FedURLPresent, "endpoint URL not set")
	} else {
		r.Pass(spec.FedURLPresent, cfg.URL)
	}

	if cfg.Profile == "" {
		r.Fail(spec.FedProfilePresent, "endpoint profile not set")
	} else {
		r.Pass(spec.FedProfilePresent, cfg.Profile)
	}

	if cfg.TrustDomain == "" {
		r.Fail(spec.FedTrustDomainPresent, "trust domain not set")
		return
	}
	r.Pass(spec.FedTrustDomainPresent, cfg.TrustDomain)
	id.CheckTrustDomain(r, "trust_domain", cfg.TrustDomain)
}

// checkProfile covers §5.2's closed set of profiles. An absent profile already
// failed FedProfilePresent, so it gets no second assertion here.
func checkProfile(r *report.Report, cfg Config) {
	switch cfg.Profile {
	case "":
		return
	case ProfileWeb, ProfileSPIFFE:
		r.Pass(spec.FedProfileKnown, cfg.Profile)
	default:
		r.Fail(spec.FedProfileKnown, fmt.Sprintf("profile=%q", cfg.Profile))
	}
}

// checkURL covers the endpoint URL requirements of §5.2.1.1 and §5.2.2.1,
// which both profiles state identically.
func checkURL(r *report.Report, cfg Config) {
	if cfg.URL == "" {
		// Already reported by FedURLPresent; there is no URL left to inspect.
		return
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		r.Fail(spec.FedURLSchemeHTTPS, fmt.Sprintf("URL parse error: %v", err))
		return
	}

	// RFC 3986 makes the scheme case-insensitive, so compare the same way the
	// SPIFFE ID checker compares "spiffe".
	if !strings.EqualFold(u.Scheme, "https") {
		r.Fail(spec.FedURLSchemeHTTPS, fmt.Sprintf("scheme=%q", u.Scheme))
	} else {
		r.Pass(spec.FedURLSchemeHTTPS, "")
	}

	if u.User != nil {
		r.Fail(spec.FedURLNoUserinfo, "userinfo present in authority")
	} else {
		r.Pass(spec.FedURLNoUserinfo, "")
	}
}

// checkProfileParams covers the per-profile parameter rules: §5.2.1.2 for
// https_web and §5.2.2.2 for https_spiffe. A profile outside the two defined
// ones already failed FedProfileKnown and has no parameter rules to apply.
func checkProfileParams(r *report.Report, cfg Config) error {
	switch cfg.Profile {
	case ProfileWeb:
		checkWebParams(r, cfg)
		return nil
	case ProfileSPIFFE:
		return checkSPIFFEParams(r, cfg)
	default:
		return nil
	}
}

func checkWebParams(r *report.Report, cfg Config) {
	var extra []string
	if cfg.EndpointID != "" {
		extra = append(extra, "endpoint SPIFFE ID")
	}
	if cfg.BundlePath != "" {
		extra = append(extra, "endpoint bundle")
	}
	if len(extra) == 0 {
		r.Pass(spec.FedWebNoExtraParams, "")
		return
	}
	r.Fail(spec.FedWebNoExtraParams, strings.Join(extra, ", ")+
		" set; did this endpoint mean profile "+ProfileSPIFFE+"?")
}

func checkSPIFFEParams(r *report.Report, cfg Config) error {
	if cfg.EndpointID == "" {
		r.Fail(spec.FedSpiffeEndpointID, "endpoint SPIFFE ID not set")
		// No SPIFFE ID means self-servingness is undecidable, so the bootstrap
		// bundle clause below has nothing to say either. A configured bundle
		// is still worth checking on its own terms.
		return checkBootstrapBundle(r, cfg)
	}
	r.Pass(spec.FedSpiffeEndpointID, cfg.EndpointID)
	id.Check(r, cfg.EndpointID)

	// §5.2.2.2: the endpoint is self-serving when its SPIFFE ID resides in the
	// same trust domain as the bundle being fetched. Only then does a
	// configuration carry its own bootstrap bundle; otherwise the endpoint's
	// trust domain is configured separately, out of this configuration's view.
	endpointTD, _, err := id.Parse(cfg.EndpointID)
	switch {
	case err != nil:
		// id.Check already reported why the ID is unusable.
	case !strings.EqualFold(endpointTD, cfg.TrustDomain):
		// Not self-serving: no vacuous assertion, matching how the bundle map
		// checker stays silent on requirements its input cannot answer.
	case cfg.BundlePath == "":
		r.Fail(spec.FedSpiffeSelfServingBundle,
			fmt.Sprintf("self-serving endpoint in %q, no bootstrap bundle configured", endpointTD))
	default:
		r.Pass(spec.FedSpiffeSelfServingBundle, cfg.BundlePath)
	}

	return checkBootstrapBundle(r, cfg)
}

// checkBootstrapBundle runs the full standalone bundle sweep over a configured
// bootstrap bundle. §5.2.2.2 requires clients to accept it in SPIFFE Bundle
// Format, so it is checked as a bundle rather than taken on trust.
func checkBootstrapBundle(r *report.Report, cfg Config) error {
	if cfg.BundlePath == "" {
		return nil
	}
	raw, err := os.ReadFile(cfg.BundlePath)
	if err != nil {
		return err
	}
	b, err := bundle.DecodeJSON(raw)
	if err != nil {
		return fmt.Errorf("endpoint bundle is not valid JSON: %w", err)
	}
	bundle.CheckObject(r, "endpoint bundle", b)
	return nil
}
