package credentialfolder_test

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kanywst/spiffe-compliance-checker/internal/credentialfolder"
	"github.com/kanywst/spiffe-compliance-checker/internal/report"
)

const (
	credName  = credentialfolder.CredentialBundleName
	trustName = "example.org" + credentialfolder.TrustBundleSuffix
)

// pki is a three-level chain for spiffe://example.org: root → intermediate →
// leaf, plus the PEM encodings the cases assemble folders from.
type pki struct {
	root, inter, leaf         *x509.Certificate
	rootPEM, interPEM         string
	leafPEM, keyPEM, otherKey string
}

// privateKey is what PKCS#8 can hold; X25519 keys cannot sign, so this is
// narrower than crypto.Signer.
type privateKey interface{ Public() crypto.PublicKey }

func newPKI(t *testing.T, leafOpts func(*x509.Certificate)) *pki {
	t.Helper()
	return newPKIWithKey(t, leafOpts, mustKey(t))
}

func newPKIWithKey(t *testing.T, leafOpts func(*x509.Certificate), leafKey privateKey) *pki {
	t.Helper()
	rootKey := mustKey(t)
	interKey := mustKey(t)
	otherKey := mustKey(t)

	td := mustURL(t, "spiffe://example.org")
	root := mustCert(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "root"},
		URIs:                  []*url.URL{td},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, nil, rootKey.Public(), rootKey)
	inter := mustCert(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "intermediate"},
		URIs:                  []*url.URL{td},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, root, interKey.Public(), rootKey)
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "leaf"},
		URIs:                  []*url.URL{mustURL(t, "spiffe://example.org/workload")},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	if leafOpts != nil {
		leafOpts(tmpl)
	}
	leaf := mustCert(t, tmpl, inter, leafKey.Public(), interKey)

	return &pki{
		root: root, inter: inter, leaf: leaf,
		rootPEM:  certPEM(root),
		interPEM: certPEM(inter),
		leafPEM:  certPEM(leaf),
		keyPEM:   keyPEM(t, leafKey),
		otherKey: keyPEM(t, otherKey),
	}
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

var serial int64

func mustCert(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	serial++
	tmpl.SerialNumber = big.NewInt(serial)
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func certPEM(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func keyPEM(t *testing.T, k privateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func folder(files map[string]string) fstest.MapFS {
	fsys := fstest.MapFS{}
	for name, content := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(content)}
	}
	return fsys
}

func TestCheck(t *testing.T) {
	p := newPKI(t, nil)
	valid := p.keyPEM + p.leafPEM + p.interPEM

	sec1 := func() string {
		k := mustKey(t)
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	}()
	withHeader := string(pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Headers: map[string]string{"Comment": "x"}, Bytes: p.inter.Raw,
	}))

	cases := []struct {
		name           string
		fsys           fstest.MapFS
		wantFailed     bool
		wantContainAny []string
	}{
		{
			name: "valid folder",
			fsys: folder(map[string]string{
				credName:  valid,
				trustName: p.rootPEM,
				// §2: other files are the provisioning system's business.
				"other.org" + credentialfolder.TrustBundleSuffix: p.rootPEM,
				"tracking.json": "{}",
			}),
			wantContainAny: []string{"3 blocks", "2 certificate(s)", "example.org.spiffe-trust-bundle.x509.pem", "!WARN", "!FAIL"},
		},
		{
			name:           "missing credential bundle",
			fsys:           folder(map[string]string{trustName: p.rootPEM}),
			wantFailed:     true,
			wantContainAny: []string{"not found (§2.3: redact by leaving the file empty"},
		},
		{
			name:           "misnamed credential bundle",
			fsys:           folder(map[string]string{"credential-bundle.pem": valid, trustName: p.rootPEM}),
			wantFailed:     true,
			wantContainAny: []string{"misnamed candidate(s): credential-bundle.pem"},
		},
		{
			name:           "empty credential bundle is a redaction",
			fsys:           folder(map[string]string{credName: "", trustName: p.rootPEM}),
			wantContainAny: []string{"empty, redacted", "!PRIVATE KEY", "!FAIL"},
		},
		{
			name:           "no trust bundles",
			fsys:           folder(map[string]string{credName: valid}),
			wantFailed:     true,
			wantContainAny: []string{"no *.spiffe-trust-bundle.x509.pem file found", "example.org.spiffe-trust-bundle.x509.pem not found"},
		},
		{
			name:           "empty trust bundle is a redaction",
			fsys:           folder(map[string]string{credName: valid, trustName: ""}),
			wantContainAny: []string{"empty, redacted", "!FAIL"},
		},
		{
			name:           "private key alone",
			fsys:           folder(map[string]string{credName: p.keyPEM, trustName: p.rootPEM}),
			wantFailed:     true,
			wantContainAny: []string{"1 block(s)"},
		},
		{
			// Compatibility Note: a coordinated provisioning system may omit
			// the key, but the MUST as written still fails.
			name:       "certificate chain without private key",
			fsys:       folder(map[string]string{credName: p.leafPEM + p.interPEM, trustName: p.rootPEM}),
			wantFailed: true,
			// The chain checks still run, on the real leaf.
			wantContainAny: []string{`first block is "CERTIFICATE"`, "2 certificate(s)", "!cA=true", "for the workload's own trust domain"},
		},
		{
			name:           "SEC1 key is not PKCS#8",
			fsys:           folder(map[string]string{credName: sec1 + p.leafPEM, trustName: p.rootPEM}),
			wantFailed:     true,
			wantContainAny: []string{`first block is "EC PRIVATE KEY"`, `block 1 is "EC PRIVATE KEY"`},
		},
		{
			name:           "PRIVATE KEY block that is not PKCS#8",
			fsys:           folder(map[string]string{credName: strings.Replace(sec1, "EC PRIVATE KEY", "PRIVATE KEY", 2) + p.leafPEM, trustName: p.rootPEM}),
			wantFailed:     true,
			wantContainAny: []string{"crypto/x509 cannot parse it as PKCS#8"},
		},
		{
			name:           "leaf does not match key",
			fsys:           folder(map[string]string{credName: p.otherKey + p.leafPEM + p.interPEM, trustName: p.rootPEM}),
			wantFailed:     true,
			wantContainAny: []string{"leaf public key does not match"},
		},
		{
			name:           "chain out of order",
			fsys:           folder(map[string]string{credName: p.keyPEM + p.interPEM + p.leafPEM, trustName: p.rootPEM}),
			wantFailed:     true,
			wantContainAny: []string{"certificate 1's issuer", "leaf public key does not match"},
		},
		{
			name:           "chain includes the root",
			fsys:           folder(map[string]string{credName: valid + p.rootPEM, trustName: p.rootPEM}),
			wantFailed:     true,
			wantContainAny: []string{"certificate 3 (CN=root) is self-signed"},
		},
		{
			// §2.2 allows an intermediate as a trust anchor; carrying it in
			// the chain then violates §2.1 even though it is not self-signed.
			name:           "chain includes an intermediate trust anchor",
			fsys:           folder(map[string]string{credName: valid, trustName: p.interPEM}),
			wantFailed:     true,
			wantContainAny: []string{"certificate 2 (CN=intermediate) is a trust anchor in this folder"},
		},
		{
			name:           "data before the first block",
			fsys:           folder(map[string]string{credName: "subject=leaf\n" + valid, trustName: p.rootPEM}),
			wantFailed:     true,
			wantContainAny: []string{"non-whitespace data outside PEM blocks"},
		},
		{
			name:           "data between blocks",
			fsys:           folder(map[string]string{credName: p.keyPEM + p.leafPEM + "# intermediate\n" + p.interPEM, trustName: p.rootPEM}),
			wantFailed:     true,
			wantContainAny: []string{"non-whitespace data outside PEM blocks"},
		},
		{
			// encoding/pem steps over a block it cannot decode; that block
			// is still inter-block data.
			name:           "malformed block skipped by the decoder",
			fsys:           folder(map[string]string{credName: p.keyPEM + "-----BEGIN CERTIFICATE-----\n!!!\n" + p.leafPEM + p.interPEM, trustName: p.rootPEM}),
			wantFailed:     true,
			wantContainAny: []string{"non-whitespace data outside PEM blocks"},
		},
		{
			name:           "blank lines between blocks are not data",
			fsys:           folder(map[string]string{credName: p.keyPEM + "\n\n" + p.leafPEM + "\n" + p.interPEM + "\n", trustName: p.rootPEM}),
			wantContainAny: []string{"!FAIL"},
		},
		{
			name:           "PEM headers",
			fsys:           folder(map[string]string{credName: p.keyPEM + p.leafPEM + withHeader, trustName: p.rootPEM}),
			wantFailed:     true,
			wantContainAny: []string{"block 3 carry PEM headers"},
		},
		{
			name:           "trust bundle with a private key",
			fsys:           folder(map[string]string{credName: valid, trustName: p.rootPEM + p.keyPEM}),
			wantFailed:     true,
			wantContainAny: []string{`example.org.spiffe-trust-bundle.x509.pem: block 2 is "PRIVATE KEY"`},
		},
		{
			name:           "trust bundle with no PEM blocks",
			fsys:           folder(map[string]string{credName: valid, trustName: "not pem\n"}),
			wantFailed:     true,
			wantContainAny: []string{"no CERTIFICATE blocks"},
		},
		{
			name:           "misnamed trust bundle",
			fsys:           folder(map[string]string{credName: valid, "example.org.trust-bundle.pem": p.rootPEM}),
			wantFailed:     true,
			wantContainAny: []string{"misnamed candidate(s): example.org.trust-bundle.pem"},
		},
		{
			// §2: other files MAY be present. A temp file from an atomic
			// write-then-rename is not a trust bundle and cannot fail one.
			name: "near-miss names alongside real bundles",
			fsys: folder(map[string]string{
				credName:                 valid,
				trustName:                p.rootPEM,
				trustName + ".tmp":       "partial",
				"trust-bundle-sync.log":  "synced",
				"credential-bundle.lock": "",
			}),
			wantContainAny: []string{"!FAIL", "!.tmp", "!sync.log"},
		},
		{
			name: "trust bundle with only a CRL",
			fsys: folder(map[string]string{
				credName:  valid,
				trustName: string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: []byte{0x30, 0}})),
			}),
			wantFailed:     true,
			wantContainAny: []string{"no CERTIFICATE blocks", `block 1 is "X509 CRL"`},
		},
		{
			// §2.1: the chain stops at the certificate preceding the anchor,
			// so a missing intermediate is caught against the own bundle.
			name:           "chain cut short",
			fsys:           folder(map[string]string{credName: p.keyPEM + p.leafPEM, trustName: p.rootPEM}),
			wantFailed:     true,
			wantContainAny: []string{`last certificate's issuer "CN=intermediate" is not an anchor in example.org.spiffe-trust-bundle.x509.pem`},
		},
		{
			// The anchor rule looks at every bundle in the folder, not only
			// the leaf's own trust domain.
			name: "chain includes a federated trust anchor",
			fsys: folder(map[string]string{
				credName:  valid,
				trustName: p.rootPEM,
				"other.org" + credentialfolder.TrustBundleSuffix: p.interPEM,
			}),
			wantFailed:     true,
			wantContainAny: []string{"certificate 2 (CN=intermediate) is a trust anchor in this folder"},
		},
		{
			name:           "truncated last block",
			fsys:           folder(map[string]string{credName: valid + "-----BEGIN CERTIFICATE-----\nMIIB", trustName: p.rootPEM}),
			wantFailed:     true,
			wantContainAny: []string{"non-whitespace data outside PEM blocks"},
		},
		{
			name: "trust bundle name is not a valid trust domain",
			fsys: folder(map[string]string{
				credName:  valid,
				trustName: p.rootPEM,
				"Other.org" + credentialfolder.TrustBundleSuffix: p.rootPEM,
			}),
			wantFailed:     true,
			wantContainAny: []string{`trust domain MUST be lowercase`, `trust_domain="Other.org"`},
		},
		{
			name:           "trust bundle with empty trust domain",
			fsys:           folder(map[string]string{credName: valid, trustName: p.rootPEM, credentialfolder.TrustBundleSuffix: p.rootPEM}),
			wantFailed:     true,
			wantContainAny: []string{"empty <trust-domain>"},
		},
		{
			name:           "own trust domain bundle missing",
			fsys:           folder(map[string]string{credName: valid, "other.org" + credentialfolder.TrustBundleSuffix: p.rootPEM}),
			wantFailed:     true,
			wantContainAny: []string{"example.org.spiffe-trust-bundle.x509.pem not found"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &report.Report{}
			if err := credentialfolder.Check(r, tc.fsys); err != nil {
				t.Fatal(err)
			}
			var buf strings.Builder
			r.Write(&buf)
			out := buf.String()

			if got := r.Failed(); got != tc.wantFailed {
				t.Fatalf("Failed()=%v, want %v\nreport:\n%s", got, tc.wantFailed, out)
			}
			for _, sub := range tc.wantContainAny {
				// A "!" prefix asserts the substring is absent.
				if want, ok := strings.CutPrefix(sub, "!"); ok {
					if strings.Contains(out, want) {
						t.Errorf("report contains %q but should not\nreport:\n%s", want, out)
					}
					continue
				}
				if !strings.Contains(out, sub) {
					t.Errorf("report missing %q\nreport:\n%s", sub, out)
				}
			}
		})
	}
}

// A leaf that is not an X.509 SVID breaks only a SHOULD, so the folder still
// passes; the X509-SVID.md MUSTs it violates are named in the warning.
func TestLeafNotSVIDWarns(t *testing.T) {
	p := newPKI(t, func(c *x509.Certificate) { c.URIs = nil })
	r := &report.Report{}
	err := credentialfolder.Check(r, folder(map[string]string{
		credName:  p.keyPEM + p.leafPEM + p.interPEM,
		trustName: p.rootPEM,
	}))
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	r.Write(&buf)
	out := buf.String()
	if r.Failed() {
		t.Fatalf("Failed()=true, want false\n%s", out)
	}
	for _, want := range []string{"WARN", "exactly one URI SAN", "scc x509-svid"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q\n%s", want, out)
		}
	}
	// With no SPIFFE ID there is no own trust domain to look up, but the
	// chain is still checked against the folder's anchors.
	if strings.Contains(out, "for the workload's own trust domain") {
		t.Errorf("own-trust-domain clause emitted for a leaf with no SPIFFE ID\n%s", out)
	}
	if !strings.Contains(out, "MUST stop at the certificate preceding the trust anchor") {
		t.Errorf("chain-complete clause not evaluated\n%s", out)
	}
}

func TestLeafIsCAWarns(t *testing.T) {
	p := newPKI(t, func(c *x509.Certificate) {
		c.IsCA = true
		c.KeyUsage = x509.KeyUsageCertSign
	})
	r := &report.Report{}
	err := credentialfolder.Check(r, folder(map[string]string{
		credName:  p.keyPEM + p.leafPEM + p.interPEM,
		trustName: p.rootPEM,
	}))
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	r.Write(&buf)
	if out := buf.String(); !strings.Contains(out, "leaf certificate has cA=true") {
		t.Errorf("report missing cA=true warning\n%s", out)
	}
}

// CheckDir must follow the symlink layout of a Kubernetes projected volume
// (Appendix B) and skip the hidden payload directory itself.
func TestCheckDirProjectedVolume(t *testing.T) {
	p := newPKI(t, nil)
	dir := t.TempDir()
	data := filepath.Join(dir, "..2026_10_29_00_00_00.000000000")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		credName:  p.keyPEM + p.leafPEM + p.interPEM,
		trustName: p.rootPEM,
	} {
		if err := os.WriteFile(filepath.Join(data, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Base(data), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{credName, trustName} {
		if err := os.Symlink(filepath.Join("..data", name), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}

	r := &report.Report{}
	if err := credentialfolder.CheckDir(r, dir); err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	r.Write(&buf)
	if out := buf.String(); r.Failed() || strings.Contains(out, "WARN") {
		t.Errorf("projected volume should pass cleanly\n%s", out)
	}
}

func TestCheckDirMissing(t *testing.T) {
	r := &report.Report{}
	if err := credentialfolder.CheckDir(r, filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("want error for a missing directory")
	}
}

// checkLeafKey must work for the signing key types crypto/x509 issues
// certificates for.
func TestLeafKeyTypes(t *testing.T) {
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]privateKey{
		"ed25519": edPriv,
		"rsa":     rsaKey,
	} {
		t.Run(name, func(t *testing.T) {
			p := newPKIWithKey(t, nil, key)
			r := &report.Report{}
			err := credentialfolder.Check(r, folder(map[string]string{
				credName:  p.keyPEM + p.leafPEM + p.interPEM,
				trustName: p.rootPEM,
			}))
			if err != nil {
				t.Fatal(err)
			}
			var buf strings.Builder
			r.Write(&buf)
			if out := buf.String(); r.Failed() {
				t.Errorf("Failed()=true, want false\n%s", out)
			}
		})
	}
}

// Entries the spec does not name are never opened, so a dangling symlink left
// by the provisioning system cannot abort the check.
func TestCheckDirIgnoresDanglingSymlink(t *testing.T) {
	p := newPKI(t, nil)
	dir := t.TempDir()
	for name, content := range map[string]string{
		credName:  p.keyPEM + p.leafPEM + p.interPEM,
		trustName: p.rootPEM,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("gone", filepath.Join(dir, "stale-tracking-link")); err != nil {
		t.Fatal(err)
	}
	r := &report.Report{}
	if err := credentialfolder.CheckDir(r, dir); err != nil {
		t.Fatalf("CheckDir: %v", err)
	}
	if r.Failed() {
		var buf strings.Builder
		r.Write(&buf)
		t.Errorf("Failed()=true, want false\n%s", buf.String())
	}
}

// An X25519 key is valid PKCS#8 even though crypto/x509 parses it into a key
// that cannot sign. crypto/x509 cannot issue a certificate for one either, so
// the leaf here does not match it; the point is that the PKCS#8 MUST passes.
func TestX25519KeyIsPKCS8(t *testing.T) {
	p := newPKI(t, nil)
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := &report.Report{}
	err = credentialfolder.Check(r, folder(map[string]string{
		credName:  keyPEM(t, x25519) + p.leafPEM + p.interPEM,
		trustName: p.rootPEM,
	}))
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	r.Write(&buf)
	out := buf.String()
	for _, a := range r.Assertions {
		if strings.Contains(a.Clause.Text, "PKCS#8") && a.Status != report.StatusPass {
			t.Errorf("PKCS#8 clause status = %v, want pass\n%s", a.Status, out)
		}
	}
	if !strings.Contains(out, "leaf public key does not match") {
		t.Errorf("report missing key mismatch\n%s", out)
	}
}

// A self-signed root that is not a well-formed CA must still read as
// self-signed; CheckSignatureFrom would refuse it as a parent.
func TestSelfSignedRootWithoutCAFlags(t *testing.T) {
	for name, tmpl := range map[string]*x509.Certificate{
		"no basic constraints": {Subject: pkix.Name{CommonName: "bare-root"}},
		"no keyCertSign": {
			Subject: pkix.Name{CommonName: "bare-root"}, IsCA: true,
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := newPKI(t, nil)
			k := mustKey(t)
			root := mustCert(t, tmpl, nil, k.Public(), k)
			r := &report.Report{}
			err := credentialfolder.Check(r, folder(map[string]string{
				credName:  p.keyPEM + p.leafPEM + p.interPEM + certPEM(root),
				trustName: p.rootPEM,
			}))
			if err != nil {
				t.Fatal(err)
			}
			var buf strings.Builder
			r.Write(&buf)
			if out := buf.String(); !strings.Contains(out, "(CN=bare-root) is self-signed") {
				t.Errorf("self-signed root not caught\n%s", out)
			}
		})
	}
}

// The chain MUST is evaluated against the whole folder when the leaf's own
// trust bundle is missing.
func TestChainCompleteWithoutOwnBundle(t *testing.T) {
	p := newPKI(t, nil)
	r := &report.Report{}
	err := credentialfolder.Check(r, folder(map[string]string{
		credName: p.keyPEM + p.leafPEM,
		"other.org" + credentialfolder.TrustBundleSuffix: p.rootPEM,
	}))
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	r.Write(&buf)
	if out := buf.String(); !strings.Contains(out, "is not an anchor in this folder") {
		t.Errorf("chain-complete not evaluated against the folder\n%s", out)
	}
}

// A spec-named entry that cannot be read is reported against its clause, and
// the rest of the folder is still checked.
func TestCheckDirUnreadableSpecFiles(t *testing.T) {
	p := newPKI(t, nil)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, trustName), []byte(p.rootPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	// Dangling symlink under the credential bundle's name.
	if err := os.Symlink("gone", filepath.Join(dir, credName)); err != nil {
		t.Fatal(err)
	}
	// A directory and an oversized file under trust bundle names.
	if err := os.Mkdir(filepath.Join(dir, "dir.org"+credentialfolder.TrustBundleSuffix), 0o700); err != nil {
		t.Fatal(err)
	}
	big := make([]byte, 1<<20+1)
	if err := os.WriteFile(filepath.Join(dir, "big.org"+credentialfolder.TrustBundleSuffix), big, 0o600); err != nil {
		t.Fatal(err)
	}

	r := &report.Report{}
	if err := credentialfolder.CheckDir(r, dir); err != nil {
		t.Fatalf("CheckDir: %v", err)
	}
	var buf strings.Builder
	r.Write(&buf)
	out := buf.String()
	if !r.Failed() {
		t.Errorf("Failed()=false, want true\n%s", out)
	}
	for _, want := range []string{
		credName + ": cannot stat",
		"dir.org.spiffe-trust-bundle.x509.pem: not a regular file",
		"big.org.spiffe-trust-bundle.x509.pem: larger than 1048576 bytes",
		"example.org.spiffe-trust-bundle.x509.pem: 1 certificate(s)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q\n%s", want, out)
		}
	}
}

// A leaf ID whose authority carries a port or userinfo has no valid trust
// domain, so it must not be stripped down to a host that finds a bundle.
func TestOwnTrustDomainRejectsPortAndUserinfo(t *testing.T) {
	for _, raw := range []string{"spiffe://example.org:8443/wl", "spiffe://user@example.org/wl"} {
		t.Run(raw, func(t *testing.T) {
			p := newPKI(t, func(c *x509.Certificate) { c.URIs = []*url.URL{mustURL(t, raw)} })
			r := &report.Report{}
			err := credentialfolder.Check(r, folder(map[string]string{
				credName:  p.keyPEM + p.leafPEM + p.interPEM,
				trustName: p.rootPEM,
			}))
			if err != nil {
				t.Fatal(err)
			}
			var buf strings.Builder
			r.Write(&buf)
			out := buf.String()
			if strings.Contains(out, "for the workload's own trust domain") {
				t.Errorf("own trust bundle looked up from %q\n%s", raw, out)
			}
			if !strings.Contains(out, "MUST stop at the certificate preceding the trust anchor") {
				t.Errorf("chain-complete not evaluated\n%s", out)
			}
		})
	}
}

// A redacted own trust bundle leaves the chain MUST to be judged against the
// rest of the folder.
func TestChainCompleteWithRedactedOwnBundle(t *testing.T) {
	p := newPKI(t, nil)
	r := &report.Report{}
	err := credentialfolder.Check(r, folder(map[string]string{
		credName:  p.keyPEM + p.leafPEM + p.interPEM,
		trustName: "",
		"other.org" + credentialfolder.TrustBundleSuffix: p.rootPEM,
	}))
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	r.Write(&buf)
	out := buf.String()
	if r.Failed() || !strings.Contains(out, "MUST stop at the certificate preceding the trust anchor") {
		t.Errorf("want chain-complete evaluated and passing against the folder\n%s", out)
	}
}

// A self-signed root crypto/x509 refuses to verify (SHA-1) is still the
// chain's anchor.
func TestSHA1SelfSignedRootIsAnchor(t *testing.T) {
	p := newPKI(t, nil)
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	root := mustCert(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "sha1-root"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		SignatureAlgorithm:    x509.SHA1WithRSA,
	}, nil, k.Public(), k)
	r := &report.Report{}
	err = credentialfolder.Check(r, folder(map[string]string{
		credName:  p.keyPEM + p.leafPEM + p.interPEM + certPEM(root),
		trustName: p.rootPEM,
	}))
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	r.Write(&buf)
	if out := buf.String(); !strings.Contains(out, "(CN=sha1-root) is self-signed") {
		t.Errorf("SHA-1 root not caught\n%s", out)
	}
}
