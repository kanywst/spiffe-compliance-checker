// Package spec is the citation table for SPIFFE spec MUST / MUST NOT / SHOULD
// clauses. Each Clause names the source document, the section, and the
// human-readable requirement text. Checkers consume clauses by name so that
// every assertion the CLI emits is traceable back to a single line in the
// spec.
package spec

// Severity records the normative force of a clause as written in the spec.
type Severity int

const (
	// SeverityMUST marks a hard requirement. Failure means the artifact is
	// non-compliant.
	SeverityMUST Severity = iota
	// SeveritySHOULD marks a recommendation. Failure is reported as a warning
	// and does not affect the exit code.
	SeveritySHOULD
)

// Clause is one normative statement from the SPIFFE spec set.
type Clause struct {
	Spec     string // file name, e.g. "SPIFFE-ID.md"
	Section  string // section anchor, e.g. "§2.1"
	Severity Severity
	Text     string // human-readable requirement
}

// SPIFFE-ID clauses (SPIFFE-ID.md).
var (
	IDSchemeSpiffe = Clause{"SPIFFE-ID.md", "§2", SeverityMUST,
		`scheme MUST be "spiffe"`}
	IDNoQueryFragment = Clause{"SPIFFE-ID.md", "§2", SeverityMUST,
		"SPIFFE ID MUST NOT include query or fragment"}
	IDTrustDomainNonEmpty = Clause{"SPIFFE-ID.md", "§2.1", SeverityMUST,
		"trust domain MUST NOT be empty"}
	IDNoUserinfo = Clause{"SPIFFE-ID.md", "§2.1", SeverityMUST,
		"authority MUST NOT contain userinfo"}
	IDNoPort = Clause{"SPIFFE-ID.md", "§2.1", SeverityMUST,
		"authority MUST NOT contain port"}
	IDTrustDomainLowercase = Clause{"SPIFFE-ID.md", "§2.1", SeverityMUST,
		"trust domain MUST be lowercase"}
	IDTrustDomainCharset = Clause{"SPIFFE-ID.md", "§2.1", SeverityMUST,
		"trust domain MUST contain only [a-z0-9.-_], no percent-encoding"}
	IDPathNoPercent = Clause{"SPIFFE-ID.md", "§2.2", SeverityMUST,
		"path MUST NOT include percent-encoded characters"}
	IDPathNoEmptyOrDot = Clause{"SPIFFE-ID.md", "§2.2", SeverityMUST,
		`path MUST NOT include empty segments or "." / ".."`}
	IDPathNoTrailingSlash = Clause{"SPIFFE-ID.md", "§2.2", SeverityMUST,
		`path MUST NOT include a trailing "/"`}
	IDPathSegmentCharset = Clause{"SPIFFE-ID.md", "§2.2", SeverityMUST,
		"path segments MUST contain only [a-zA-Z0-9.-_]"}
	// §2.3 splits the requirement: implementations MUST support up to
	// 2048 bytes (a consumer-side rule), but generators only SHOULD NOT
	// exceed it. Since this checker validates artifacts, the relevant
	// severity is the generator-side SHOULD NOT.
	IDLengthLimit = Clause{"SPIFFE-ID.md", "§2.3", SeveritySHOULD,
		"SPIFFE ID SHOULD NOT exceed 2048 bytes"}
	IDTrustDomainLengthLimit = Clause{"SPIFFE-ID.md", "§2.3", SeverityMUST,
		"trust domain MUST be at most 255 bytes"}
)

// X.509-SVID clauses (X509-SVID.md).
var (
	X509URISANCountOne = Clause{"X509-SVID.md", "§2", SeverityMUST,
		"X.509-SVID MUST contain exactly one URI SAN"}
	X509LeafNonRootPath = Clause{"X509-SVID.md", "§3.1", SeverityMUST,
		"leaf SPIFFE ID MUST have a non-root path component"}
	X509SANCriticalWhenNoSubject = Clause{"X509-SVID.md", "§3.1", SeverityMUST,
		"URI SAN extension MUST be marked critical when Subject is omitted"}
	X509SigningNoPath = Clause{"X509-SVID.md", "§3.2", SeverityMUST,
		"signing certificate SPIFFE ID MUST NOT have a path component"}
	X509SigningCATrue = Clause{"X509-SVID.md", "§4.1", SeverityMUST,
		"signing certificate MUST set Basic Constraints cA=true"}
	X509LeafCAFalse = Clause{"X509-SVID.md", "§4.1", SeverityMUST,
		"leaf certificate MUST set Basic Constraints cA=false"}
	X509KeyUsageCritical = Clause{"X509-SVID.md", "§4.3", SeverityMUST,
		"Key Usage extension MUST be set and marked critical"}
	X509SigningKeyCertSign = Clause{"X509-SVID.md", "§4.3", SeverityMUST,
		"signing certificate MUST set keyCertSign in Key Usage"}
	X509SigningNoOtherKeyUsage = Clause{"X509-SVID.md", "App. A", SeverityMUST,
		"signing certificate Key Usage MUST be limited to keyCertSign and (optionally) cRLSign"}
	X509LeafDigitalSignature = Clause{"X509-SVID.md", "§4.3", SeverityMUST,
		"leaf certificate MUST set digitalSignature in Key Usage"}
	X509LeafNoKeyCertSign = Clause{"X509-SVID.md", "§4.3", SeverityMUST,
		"leaf certificate MUST NOT set keyCertSign or cRLSign in Key Usage"}
	X509LeafEKURecommended = Clause{"X509-SVID.md", "§4.4", SeveritySHOULD,
		"leaf certificate SHOULD include Extended Key Usage extension"}
	X509EKUServerAndClient = Clause{"X509-SVID.md", "§4.4", SeverityMUST,
		"when EKU is set, id-kp-serverAuth and id-kp-clientAuth MUST both be present"}
)

// JWT-SVID clauses (JWT-SVID.md).
var (
	JWTCompactSerialization = Clause{"JWT-SVID.md", "§1", SeverityMUST,
		"JWT-SVID MUST use JWS Compact Serialization, not JWS JSON Serialization"}
	JWTAlgWhitelist = Clause{"JWT-SVID.md", "§2.1", SeverityMUST,
		"alg MUST be one of RS{256,384,512}, PS{256,384,512}, ES{256,384,512}"}
	JWTTypValue = Clause{"JWT-SVID.md", "§2.3", SeverityMUST,
		`if typ header is set, value MUST be "JWT" or "JOSE"`}
	JWTSubPresent = Clause{"JWT-SVID.md", "§3.1", SeverityMUST,
		"sub claim MUST be set to a SPIFFE ID"}
	JWTAudPresent = Clause{"JWT-SVID.md", "§3.2", SeverityMUST,
		"aud claim MUST be present with one or more values"}
	JWTAudSingleRecommended = Clause{"JWT-SVID.md", "§3.2", SeveritySHOULD,
		"aud SHOULD contain a single value to limit replay scope"}
	JWTExpPresent = Clause{"JWT-SVID.md", "§3.3", SeverityMUST,
		"exp claim MUST be set"}
	JWTExpNotInPast = Clause{"JWT-SVID.md", "App. A", SeverityMUST,
		"exp MUST NOT be in the past (small leeway acceptable)"}
)

// Bundle clauses (SPIFFE_Trust_Domain_and_Bundle.md, plus per-SVID-spec
// bundle requirements).
var (
	BundleKeysPresent = Clause{"SPIFFE_Trust_Domain_and_Bundle.md", "§4.1.3", SeverityMUST,
		`"keys" parameter MUST be present`}
	BundleKeyKTYSet = Clause{"SPIFFE_Trust_Domain_and_Bundle.md", "§4.2.1", SeverityMUST,
		`each key MUST set "kty"`}
	BundleKeyUseSet = Clause{"SPIFFE_Trust_Domain_and_Bundle.md", "§4.2.2", SeverityMUST,
		`each key MUST set "use" to "x509-svid" or "jwt-svid"`}
	BundleSequenceMonotonic = Clause{"SPIFFE_Trust_Domain_and_Bundle.md", "§4.1.1", SeveritySHOULD,
		`"spiffe_sequence" SHOULD be set; when present MUST be a monotonically increasing integer`}
	BundleRefreshHintInteger = Clause{"SPIFFE_Trust_Domain_and_Bundle.md", "§4.1.2", SeveritySHOULD,
		`"spiffe_refresh_hint" SHOULD be set; when present MUST be an integer in seconds`}
	BundleX509X5CPresent = Clause{"X509-SVID.md", "§6.1", SeverityMUST,
		`x509-svid JWK entry MUST contain "x5c" with exactly one base64 DER CA certificate`}
	BundleX509SelfSigned = Clause{"X509-SVID.md", "§6.1", SeveritySHOULD,
		"x509-svid CA certificate SHOULD be self-signed"}
	BundleX509NoKid = Clause{"X509-SVID.md", "§6.1", SeverityMUST,
		`x509-svid JWK entry MUST NOT set "kid"`}
	BundleJWTKidPresent = Clause{"JWT-SVID.md", "§6.1", SeverityMUST,
		`jwt-svid JWK entry MUST set "kid"`}
)
