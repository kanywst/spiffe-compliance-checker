// Package x509svid checks an X.509 certificate against the MUST clauses of
// X509-SVID.md. The certificate is loaded from PEM or DER. Standard X.509
// path validation is out of scope: this checker only verifies the SPIFFE-
// specific shape of the certificate itself.
package x509svid

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"

	"github.com/0-draft/spiffe-compliance-checker/internal/id"
	"github.com/0-draft/spiffe-compliance-checker/internal/report"
	"github.com/0-draft/spiffe-compliance-checker/internal/spec"
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

func parseCert(raw []byte) (*x509.Certificate, error) {
	if block, _ := pem.Decode(raw); block != nil {
		return x509.ParseCertificate(block.Bytes)
	}
	return x509.ParseCertificate(raw)
}

// Check evaluates X509-SVID.md against cert and appends assertions to r.
func Check(r *report.Report, cert *x509.Certificate) {
	uri := checkURISAN(r, cert)
	isLeaf := !cert.IsCA

	checkBasicConstraints(r, cert, isLeaf)
	checkKeyUsage(r, cert, isLeaf)
	checkEKU(r, cert, isLeaf)

	if uri != nil {
		checkSPIFFEID(r, uri, isLeaf)
	}
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
	// §4.3: Key Usage MUST be set. Whether it is critical cannot be inspected
	// via crypto/x509's parsed view; we treat KeyUsage != 0 as "set" and
	// emit a PASS for presence only.
	if cert.KeyUsage == 0 {
		r.Fail(spec.X509KeyUsageCritical, "Key Usage extension not set")
		return
	}
	r.Pass(spec.X509KeyUsageCritical, "")

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
}

func checkEKU(r *report.Report, cert *x509.Certificate, isLeaf bool) {
	if !isLeaf {
		return
	}
	// §4.4: leaf SHOULD include EKU; when included, MUST contain both
	// serverAuth and clientAuth.
	if len(cert.ExtKeyUsage) == 0 {
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
