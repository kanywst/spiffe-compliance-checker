package x509svid_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/spiffe-compliance-checker/internal/report"
	"github.com/kanywst/spiffe-compliance-checker/internal/x509svid"
)

type certOpts struct {
	uris        []*url.URL
	isCA        bool
	keyUsage    x509.KeyUsage
	extKeyUsage []x509.ExtKeyUsage
}

func mkCert(t *testing.T, opts certOpts) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              opts.keyUsage,
		ExtKeyUsage:           opts.extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  opts.isCA,
		URIs:                  opts.uris,
		Subject:               pkix.Name{},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func mustURI(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestLeafValid(t *testing.T) {
	cert := mkCert(t, certOpts{
		uris:     []*url.URL{mustURI(t, "spiffe://example.com/payments/web-fe")},
		isCA:     false,
		keyUsage: x509.KeyUsageDigitalSignature,
		extKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	})
	r := &report.Report{}
	x509svid.Check(r, cert)
	if r.Failed() {
		var buf strings.Builder
		r.Write(&buf)
		t.Fatalf("valid leaf failed:\n%s", buf.String())
	}
}

func TestSigningValid(t *testing.T) {
	cert := mkCert(t, certOpts{
		uris:     []*url.URL{mustURI(t, "spiffe://example.com")},
		isCA:     true,
		keyUsage: x509.KeyUsageCertSign,
	})
	r := &report.Report{}
	x509svid.Check(r, cert)
	if r.Failed() {
		var buf strings.Builder
		r.Write(&buf)
		t.Fatalf("valid signing cert failed:\n%s", buf.String())
	}
}

func TestLeafFailures(t *testing.T) {
	cases := []struct {
		name           string
		opts           certOpts
		wantContainAny []string
	}{
		{
			name: "no URI SAN",
			opts: certOpts{
				isCA:        false,
				keyUsage:    x509.KeyUsageDigitalSignature,
				extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			},
			wantContainAny: []string{"exactly one URI SAN"},
		},
		{
			name: "two URI SANs",
			opts: certOpts{
				uris: []*url.URL{
					mustURI(t, "spiffe://example.com/a"),
					mustURI(t, "spiffe://example.com/b"),
				},
				isCA:        false,
				keyUsage:    x509.KeyUsageDigitalSignature,
				extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			},
			wantContainAny: []string{"exactly one URI SAN"},
		},
		{
			name: "leaf with root path",
			opts: certOpts{
				uris:        []*url.URL{mustURI(t, "spiffe://example.com")},
				isCA:        false,
				keyUsage:    x509.KeyUsageDigitalSignature,
				extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			},
			wantContainAny: []string{"non-root path"},
		},
		{
			name: "leaf without digitalSignature",
			opts: certOpts{
				uris:        []*url.URL{mustURI(t, "spiffe://example.com/a")},
				isCA:        false,
				keyUsage:    x509.KeyUsageKeyEncipherment,
				extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			},
			wantContainAny: []string{"digitalSignature"},
		},
		{
			name: "leaf with keyCertSign (forbidden)",
			opts: certOpts{
				uris:        []*url.URL{mustURI(t, "spiffe://example.com/a")},
				isCA:        false,
				keyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
				extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			},
			wantContainAny: []string{"MUST NOT set keyCertSign"},
		},
		{
			name: "leaf EKU missing clientAuth",
			opts: certOpts{
				uris:        []*url.URL{mustURI(t, "spiffe://example.com/a")},
				isCA:        false,
				keyUsage:    x509.KeyUsageDigitalSignature,
				extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			},
			wantContainAny: []string{"serverAuth=true clientAuth=false"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert := mkCert(t, tc.opts)
			r := &report.Report{}
			x509svid.Check(r, cert)
			if !r.Failed() {
				var buf strings.Builder
				r.Write(&buf)
				t.Fatalf("expected failure for %s\nreport:\n%s", tc.name, buf.String())
			}
			var buf strings.Builder
			r.Write(&buf)
			out := buf.String()
			for _, sub := range tc.wantContainAny {
				if !strings.Contains(out, sub) {
					t.Errorf("expected %q in report\nreport:\n%s", sub, out)
				}
			}
		})
	}
}

func TestKeyUsageNotCriticalFails(t *testing.T) {
	// Build a cert with KU present but explicitly NOT critical by hand-
	// rolling the extension. Go's x509.CreateCertificate always sets KU
	// critical when populated via the high-level fields, so we override
	// via ExtraExtensions.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// KU bit pattern: digitalSignature (bit 0). DER encoding of BIT STRING
	// `1000 0000` is 03 02 07 80.
	kuValue := []byte{0x03, 0x02, 0x07, 0x80}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{mustURI(t, "spiffe://example.com/a")},
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: false, Value: kuValue},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	r := &report.Report{}
	x509svid.Check(r, cert)
	if !r.Failed() {
		t.Fatal("expected failure when KU not marked critical")
	}
	var buf strings.Builder
	r.Write(&buf)
	if !strings.Contains(buf.String(), "not marked critical") {
		t.Errorf("expected 'not marked critical' in report:\n%s", buf.String())
	}
}

func TestNilCertIsNoOp(t *testing.T) {
	r := &report.Report{}
	x509svid.Check(r, nil)
	if r.Failed() || len(r.Assertions) != 0 {
		t.Fatalf("nil cert should be a no-op, got %d assertions", len(r.Assertions))
	}
}

func TestSigningWithForbiddenKeyUsageFails(t *testing.T) {
	cases := []struct {
		name string
		ku   x509.KeyUsage
	}{
		{"digitalSignature (leaf-only)", x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature},
		{"dataEncipherment (outside both sets)", x509.KeyUsageCertSign | x509.KeyUsageDataEncipherment},
		{"contentCommitment (outside both sets)", x509.KeyUsageCertSign | x509.KeyUsageContentCommitment},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert := mkCert(t, certOpts{
				uris:     []*url.URL{mustURI(t, "spiffe://example.com")},
				isCA:     true,
				keyUsage: tc.ku,
			})
			r := &report.Report{}
			x509svid.Check(r, cert)
			if !r.Failed() {
				t.Fatalf("expected failure when signing cert sets %s", tc.name)
			}
			var buf strings.Builder
			r.Write(&buf)
			if !strings.Contains(buf.String(), "outside {keyCertSign, cRLSign}") {
				t.Errorf("expected forbidden-bits message in report:\n%s", buf.String())
			}
		})
	}
}

func TestLeafEKUWithUnknownOIDStillTriggersCheck(t *testing.T) {
	// Cert has an EKU extension but Go can't recognise the OID, so the
	// parsed cert.ExtKeyUsage is empty while cert.UnknownExtKeyUsage has
	// one entry. The presence check must use both fields.
	unknownOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		URIs:                  []*url.URL{mustURI(t, "spiffe://example.com/a")},
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{unknownOID},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.ExtKeyUsage) != 0 {
		t.Fatalf("test precondition: expected ExtKeyUsage empty, got %v", cert.ExtKeyUsage)
	}
	if len(cert.UnknownExtKeyUsage) == 0 {
		t.Fatal("test precondition: expected UnknownExtKeyUsage populated")
	}
	r := &report.Report{}
	x509svid.Check(r, cert)
	// EKU is present (via the unknown OID) but serverAuth/clientAuth are
	// missing, so the MUST clause should fail, not be skipped.
	if !r.Failed() {
		var buf strings.Builder
		r.Write(&buf)
		t.Fatalf("expected serverAuth/clientAuth failure:\n%s", buf.String())
	}
	var buf strings.Builder
	r.Write(&buf)
	if !strings.Contains(buf.String(), "serverAuth=false clientAuth=false") {
		t.Errorf("expected EKU MUST-bits failure, got:\n%s", buf.String())
	}
}

func TestParseCertHandlesMultiBlockPEM(t *testing.T) {
	// Generate a valid leaf and emit a PEM file that has a fake private-key
	// block first, then the CERTIFICATE block. The old single-block decoder
	// would have stopped at the first block and failed to parse.
	cert := mkCert(t, certOpts{
		uris:     []*url.URL{mustURI(t, "spiffe://example.com/a")},
		isCA:     false,
		keyUsage: x509.KeyUsageDigitalSignature,
		extKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	})
	var buf strings.Builder
	buf.WriteString("-----BEGIN PRIVATE KEY-----\n")
	buf.WriteString("MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n")
	buf.WriteString("-----END PRIVATE KEY-----\n")
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir() + "/cert.pem"
	if err := os.WriteFile(tmp, []byte(buf.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &report.Report{}
	if err := x509svid.CheckFile(r, tmp); err != nil {
		t.Fatalf("CheckFile on multi-block PEM failed: %v", err)
	}
	if r.Failed() {
		var got strings.Builder
		r.Write(&got)
		t.Fatalf("multi-block PEM with valid leaf should pass:\n%s", got.String())
	}
}

func TestSigningWithPathFails(t *testing.T) {
	cert := mkCert(t, certOpts{
		uris:     []*url.URL{mustURI(t, "spiffe://example.com/intermediate")},
		isCA:     true,
		keyUsage: x509.KeyUsageCertSign,
	})
	r := &report.Report{}
	x509svid.Check(r, cert)
	if !r.Failed() {
		var buf strings.Builder
		r.Write(&buf)
		t.Fatalf("expected failure for signing cert with path\nreport:\n%s", buf.String())
	}
	var buf strings.Builder
	r.Write(&buf)
	if !strings.Contains(buf.String(), "MUST NOT have a path") {
		t.Errorf("expected 'MUST NOT have a path' in report:\n%s", buf.String())
	}
}
