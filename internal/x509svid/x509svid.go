// Package x509svid checks an X.509 certificate against the MUST clauses of
// X509-SVID.md. The certificate is loaded from PEM or DER. Standard X.509
// path validation is out of scope: this checker only verifies the SPIFFE-
// specific shape of the certificate itself.
package x509svid

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"

	"github.com/0-draft/spiffe-compliance-checker/internal/id"
	"github.com/0-draft/spiffe-compliance-checker/internal/report"
	"github.com/0-draft/spiffe-compliance-checker/internal/spec"
)

// RFC 5280 standard X.509 extension OIDs.
var (
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// CheckFile reads a certificate from path and runs Check on it.
func CheckFile(r *report.Report, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	cert, err := parseCert(raw)
	if err != nil {
		return err
	}
	Check(r, cert)
	return nil
}

// parseCert decodes a certificate from PEM (handling files where the
// CERTIFICATE block is preceded by a private key or other PEM blocks) or
// falls back to raw DER.
func parseCert(raw []byte) (*x509.Certificate, error) {
	rest := raw
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
		rest = next
	}
	return x509.ParseCertificate(raw)
}

// Check evaluates X509-SVID.md against cert and appends assertions to r. A
// nil cert is treated as a no-op so callers do not need to guard against
// parse failures upstream.
func Check(r *report.Report, cert *x509.Certificate) {
	if cert == nil {
		return
	}
	uri := checkURISAN(r, cert)
	isLeaf := !cert.IsCA

	checkBasicConstraints(r, cert, isLeaf)
	checkKeyUsage(r, cert, isLeaf)
	checkEKU(r, cert, isLeaf)
	checkSANCritical(r, cert)

	if uri != nil {
		checkSPIFFEID(r, uri, isLeaf)
	}
}

// extensionCritical reports whether the extension with the given OID is
// present in cert and, if so, whether it is marked critical.
func extensionCritical(cert *x509.Certificate, oid asn1.ObjectIdentifier) (critical, found bool) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return ext.Critical, true
		}
	}
	return false, false
}

func checkURISAN(r *report.Report, cert *x509.Certificate) *url.URL {
	// §2: MUST contain exactly one URI SAN.
	n := len(cert.URIs)
	if n != 1 {
		r.Fail(spec.X509URISANCountOne, fmt.Sprintf("found %d URI SAN(s)", n))
		return nil
	}
	r.Pass(spec.X509URISANCountOne, "")
	return cert.URIs[0]
}

func checkBasicConstraints(r *report.Report, cert *x509.Certificate, isLeaf bool) {
	switch {
	case isLeaf:
		// §4.1: leaf MUST set cA=false. crypto/x509 surfaces this as
		// IsCA=false plus BasicConstraintsValid.
		if cert.BasicConstraintsValid && !cert.IsCA {
			r.Pass(spec.X509LeafCAFalse, "")
		} else {
			r.Fail(spec.X509LeafCAFalse,
				fmt.Sprintf("BasicConstraintsValid=%v, IsCA=%v",
					cert.BasicConstraintsValid, cert.IsCA))
		}
	default:
		// §4.1: signing MUST set cA=true.
		if cert.BasicConstraintsValid && cert.IsCA {
			r.Pass(spec.X509SigningCATrue, "")
		} else {
			r.Fail(spec.X509SigningCATrue,
				fmt.Sprintf("BasicConstraintsValid=%v, IsCA=%v",
					cert.BasicConstraintsValid, cert.IsCA))
		}
	}
}

func checkKeyUsage(r *report.Report, cert *x509.Certificate, isLeaf bool) {
	// §4.3: Key Usage MUST be set and MUST be marked critical. Both
	// conditions are inspected on the raw extension so we catch the
	// criticality flag, which crypto/x509's parsed KeyUsage field discards.
	crit, found := extensionCritical(cert, oidKeyUsage)
	switch {
	case !found:
		r.Fail(spec.X509KeyUsageCritical, "Key Usage extension absent")
		return
	case !crit:
		r.Fail(spec.X509KeyUsageCritical, "Key Usage extension not marked critical")
	default:
		r.Pass(spec.X509KeyUsageCritical, "")
	}

	if isLeaf {
		// digitalSignature MUST be set.
		if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
			r.Pass(spec.X509LeafDigitalSignature, "")
		} else {
			r.Fail(spec.X509LeafDigitalSignature, "")
		}
		// keyCertSign and cRLSign MUST NOT be set.
		bad := cert.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0
		if bad {
			r.Fail(spec.X509LeafNoKeyCertSign,
				fmt.Sprintf("KeyUsage=0x%x has CertSign or CRLSign", cert.KeyUsage))
		} else {
			r.Pass(spec.X509LeafNoKeyCertSign, "")
		}
		return
	}

	// Signing certificate: keyCertSign MUST be set.
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		r.Pass(spec.X509SigningKeyCertSign, "")
	} else {
		r.Fail(spec.X509SigningKeyCertSign,
			fmt.Sprintf("KeyUsage=0x%x missing CertSign", cert.KeyUsage))
	}

	// Per X509-SVID.md Appendix A: signing certs MUST be limited to
	// keyCertSign and (optionally) cRLSign. Bitmask-out the permitted set
	// and any remaining bit (digitalSignature, keyEncipherment,
	// keyAgreement, dataEncipherment, contentCommitment, encipherOnly,
	// decipherOnly) is a violation.
	const allowedSigningKU = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if cert.KeyUsage&^allowedSigningKU != 0 {
		r.Fail(spec.X509SigningNoOtherKeyUsage,
			fmt.Sprintf("KeyUsage=0x%x sets bits outside {keyCertSign, cRLSign}", cert.KeyUsage))
	} else {
		r.Pass(spec.X509SigningNoOtherKeyUsage, "")
	}
}

// checkSANCritical enforces X509-SVID.md §3.1: when Subject is omitted, the
// SAN extension MUST be marked critical.
func checkSANCritical(r *report.Report, cert *x509.Certificate) {
	if len(cert.Subject.Names) > 0 {
		return // Subject present, the conditional clause does not apply.
	}
	crit, found := extensionCritical(cert, oidSubjectAltName)
	if !found {
		return // already caught by URI SAN count check
	}
	if !crit {
		r.Fail(spec.X509SANCriticalWhenNoSubject,
			"Subject is empty but SAN extension is not marked critical")
		return
	}
	r.Pass(spec.X509SANCriticalWhenNoSubject, "")
}

func checkEKU(r *report.Report, cert *x509.Certificate, isLeaf bool) {
	if !isLeaf {
		return
	}
	// §4.4: leaf SHOULD include EKU; when included, MUST contain both
	// serverAuth and clientAuth. EKU "presence" includes the case where
	// the extension is set but contains only OIDs Go does not recognize
	// (those land in UnknownExtKeyUsage, leaving ExtKeyUsage empty).
	if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
		r.Fail(spec.X509LeafEKURecommended, "EKU extension absent")
		return
	}
	r.Pass(spec.X509LeafEKURecommended, "")
	hasServer, hasClient := false, false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServer = true
		}
		if eku == x509.ExtKeyUsageClientAuth {
			hasClient = true
		}
	}
	if hasServer && hasClient {
		r.Pass(spec.X509EKUServerAndClient, "")
	} else {
		r.Fail(spec.X509EKUServerAndClient,
			fmt.Sprintf("serverAuth=%v clientAuth=%v", hasServer, hasClient))
	}
}

func checkSPIFFEID(r *report.Report, u *url.URL, isLeaf bool) {
	id.Check(r, u.String())
	_, path, err := id.Parse(u.String())
	if err != nil {
		return
	}
	if isLeaf {
		// §3.1 / §5.2: leaf SPIFFE ID MUST have a non-root path component.
		if path == "" || path == "/" {
			r.Fail(spec.X509LeafNonRootPath, fmt.Sprintf("path=%q", path))
		} else {
			r.Pass(spec.X509LeafNonRootPath, "")
		}
	} else {
		// §3.2: signing certificate SPIFFE ID MUST NOT have a path component.
		if path != "" && path != "/" {
			r.Fail(spec.X509SigningNoPath, fmt.Sprintf("path=%q", path))
		} else {
			r.Pass(spec.X509SigningNoPath, "")
		}
	}
}
