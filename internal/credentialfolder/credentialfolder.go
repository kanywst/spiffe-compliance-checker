// Package credentialfolder checks a SPIFFE credential folder — the directory a
// provisioning system writes X.509 SVIDs and trust bundles into — against §2 of
// SPIFFE_Filesystem_Delivery.md.
//
// §2 fixes the folder's shape: one credential bundle holding the private key
// and certificate chain, one trust bundle per trust domain, each a PEM file
// with a fixed name and a restricted set of block types. §3 is about how an
// application loads and refreshes those files, and the SHOULDs on atomic
// updates and on keeping the folder off physical disks describe the
// provisioning system's behaviour, so both stay out of scope.
package credentialfolder

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/kanywst/spiffe-compliance-checker/internal/id"
	"github.com/kanywst/spiffe-compliance-checker/internal/report"
	"github.com/kanywst/spiffe-compliance-checker/internal/spec"
	"github.com/kanywst/spiffe-compliance-checker/internal/x509svid"
)

// File names fixed by SPIFFE_Filesystem_Delivery.md §2.
const (
	CredentialBundleName = "credential-bundle.private-key.x509.pem"
	TrustBundleSuffix    = ".spiffe-trust-bundle.x509.pem"
)

// PEM block types §2.1 and §2.2 allow.
const (
	typePrivateKey  = "PRIVATE KEY"
	typeCertificate = "CERTIFICATE"
)

// trustBundle is one <trust-domain>.spiffe-trust-bundle.x509.pem file.
type trustBundle struct {
	name        string
	trustDomain string
	raw         []byte
	problem     string // why the file could not be read; raw is nil then
}

// maxFileSize caps how much of a bundle file is read. A real credential or
// trust bundle is a few kilobytes; the cap only keeps a hostile folder from
// exhausting memory.
const maxFileSize = 1 << 20

// CheckDir runs Check on the credential folder at dir.
func CheckDir(r *report.Report, dir string) error {
	return Check(r, os.DirFS(dir))
}

// Check evaluates the credential folder fsys against SPIFFE_Filesystem_Delivery.md
// §2 and appends the assertions to r. It returns an error only when the folder
// itself cannot be listed, which leaves nothing to check.
//
// §2 lets a folder hold other files and directories for the provisioning
// system's own use, so an entry is classified by name before it is touched and
// anything the spec does not name is never opened — a dangling symlink or an
// unreadable tracking file must not stop the check. A spec-named entry that
// cannot be read is a finding about that file, not a reason to stop: it is
// reported against its clause and the rest of the folder is still checked.
// Kubernetes projected volumes, the spec's own reference example, keep their
// payload behind symlinks into a hidden "..data" directory, and fs.Stat
// follows those links.
func Check(r *report.Report, fsys fs.FS) error {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return err
	}

	var (
		cred         []byte
		credFound    bool
		credProblem  string
		trust        []trustBundle
		misnamed     []string
		credMisnamed []string
	)
	for _, e := range entries {
		name := e.Name()
		lower := strings.ToLower(name)
		isCred := name == CredentialBundleName
		isTrust := strings.HasSuffix(name, TrustBundleSuffix)
		if !isCred && !isTrust {
			// Near misses are only named in a presence failure's detail: a
			// file outside the spec's names is not a bundle, so it cannot
			// violate a bundle clause (§2: other files MAY be present).
			switch {
			case strings.Contains(lower, "trust-bundle"):
				misnamed = append(misnamed, name)
			case strings.Contains(lower, "credential-bundle"):
				credMisnamed = append(credMisnamed, name)
			}
			continue
		}
		raw, problem := readSpecFile(fsys, name)
		if isCred {
			cred, credFound, credProblem = raw, true, problem
			continue
		}
		trust = append(trust, trustBundle{name, strings.TrimSuffix(name, TrustBundleSuffix), raw, problem})
	}

	checkPresence(r, credFound, len(cred) == 0, credProblem, credMisnamed, misnamed, trust)

	var chain []*x509.Certificate
	if credFound && credProblem == "" && len(cred) > 0 {
		chain = checkCredentialBundle(r, cred, anchors(trust))
	}

	for _, tb := range trust {
		checkTrustBundle(r, tb)
	}

	if chain != nil {
		checkOwnTrustBundle(r, chain, trust)
	}
	return nil
}

// readSpecFile reads a spec-named file, or says why it cannot. Only a regular
// file is opened: opening a FIFO with that name would block forever, and a
// directory or device is not a PEM file in the first place.
func readSpecFile(fsys fs.FS, name string) (raw []byte, problem string) {
	info, err := fs.Stat(fsys, name)
	if err != nil {
		return nil, "cannot stat: " + err.Error()
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Sprintf("not a regular file (mode %s)", info.Mode())
	}
	f, err := fsys.Open(name)
	if err != nil {
		return nil, "cannot open: " + err.Error()
	}
	defer func() { _ = f.Close() }()
	raw, err = io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, "cannot read: " + err.Error()
	}
	if len(raw) > maxFileSize {
		return nil, fmt.Sprintf("larger than %d bytes", maxFileSize)
	}
	return raw, ""
}

// checkPresence covers §2's two required names. An empty file counts as
// present: §2.3 defines it as a redaction, and the per-file checks are skipped
// for it rather than failing on a missing PEM block.
func checkPresence(r *report.Report, credFound, credEmpty bool, credProblem string, credMisnamed, trustMisnamed []string, trust []trustBundle) {
	switch {
	case credProblem != "":
		r.Fail(spec.FSDCredentialBundlePresent, CredentialBundleName+": "+credProblem)
	case !credFound && len(credMisnamed) > 0:
		r.Fail(spec.FSDCredentialBundlePresent,
			fmt.Sprintf("%s not found; misnamed candidate(s): %s", CredentialBundleName, strings.Join(credMisnamed, ", ")))
	case !credFound:
		r.Fail(spec.FSDCredentialBundlePresent,
			CredentialBundleName+" not found (§2.3: redact by leaving the file empty, not by removing it)")
	case credEmpty:
		r.Pass(spec.FSDCredentialBundlePresent, CredentialBundleName+": empty, redacted (§2.3)")
	default:
		r.Pass(spec.FSDCredentialBundlePresent, "")
	}

	switch {
	case len(trust) == 0 && len(trustMisnamed) > 0:
		r.Fail(spec.FSDTrustBundlePresent,
			fmt.Sprintf("no *%s file found; misnamed candidate(s): %s", TrustBundleSuffix, strings.Join(trustMisnamed, ", ")))
		return
	case len(trust) == 0:
		r.Fail(spec.FSDTrustBundlePresent, "no *"+TrustBundleSuffix+" file found")
		return
	}
	names := make([]string, len(trust))
	for i, tb := range trust {
		names[i] = tb.name
	}
	r.Pass(spec.FSDTrustBundlePresent, strings.Join(names, ", "))
}

// anchors collects every certificate in the folder's trust bundles, so the
// credential bundle can be checked for a trust anchor it must not carry.
// Malformed content is skipped here; checkTrustBundle reports it.
func anchors(trust []trustBundle) []*x509.Certificate {
	var out []*x509.Certificate
	for _, tb := range trust {
		blocks, _ := splitPEM(tb.raw)
		for _, b := range blocks {
			if b.Type != typeCertificate {
				continue
			}
			if c, err := x509.ParseCertificate(b.Bytes); err == nil {
				out = append(out, c)
			}
		}
	}
	return out
}

// checkCredentialBundle covers §2.1. It returns the certificate chain when it
// parsed, so the caller can check it against the trust bundle for the leaf's
// trust domain.
func checkCredentialBundle(r *report.Report, raw []byte, trustAnchors []*x509.Certificate) []*x509.Certificate {
	const tag = CredentialBundleName
	blocks, interBlock := splitPEM(raw)

	if len(blocks) >= 2 {
		r.Pass(spec.FSDCredentialBundleBlocks, annotate(tag, fmt.Sprintf("%d blocks", len(blocks))))
	} else {
		r.Fail(spec.FSDCredentialBundleBlocks, annotate(tag, fmt.Sprintf("%d block(s)", len(blocks))))
	}
	checkFileShape(r, tag, blocks, interBlock, typePrivateKey, typeCertificate)
	if len(blocks) == 0 {
		return nil
	}

	key := checkPrivateKey(r, tag, blocks[0])
	// When the key is omitted — the Compatibility Note case, which the
	// PRIVATE KEY MUST has already failed — the chain starts at block 1, and
	// the leaf checks must run on the real leaf, not on its issuer.
	chainBlocks, first := blocks[1:], 2
	if blocks[0].Type == typeCertificate {
		chainBlocks, first = blocks, 1
	}
	if len(chainBlocks) == 0 {
		return nil
	}
	certs := checkChainBlocks(r, tag, chainBlocks, first)
	if certs == nil {
		return nil
	}
	leaf := certs[0]

	checkChainOrder(r, tag, certs)
	if key != nil {
		checkLeafKey(r, tag, leaf, key)
	}
	checkLeafSVID(r, tag, leaf)
	checkNoTrustAnchor(r, tag, certs, trustAnchors)
	return certs
}

// checkPrivateKey covers the first-block MUST and returns the parsed key.
func checkPrivateKey(r *report.Report, tag string, b *pem.Block) crypto.PublicKey {
	if b.Type != typePrivateKey {
		r.Fail(spec.FSDCredentialBundlePrivateKey, annotate(tag, fmt.Sprintf("first block is %q", b.Type)))
		return nil
	}
	key, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		// crypto/x509 also rejects well-formed PKCS#8 for algorithms it does
		// not implement, so the detail says whose verdict this is.
		r.Fail(spec.FSDCredentialBundlePrivateKey, annotate(tag, "crypto/x509 cannot parse it as PKCS#8: "+err.Error()))
		return nil
	}
	// Public() rather than crypto.Signer: an X25519 key (*ecdh.PrivateKey)
	// is valid PKCS#8 but cannot sign.
	priv, ok := key.(interface{ Public() crypto.PublicKey })
	if !ok {
		r.Fail(spec.FSDCredentialBundlePrivateKey, annotate(tag, fmt.Sprintf("unsupported key type %T", key)))
		return nil
	}
	r.Pass(spec.FSDCredentialBundlePrivateKey, annotate(tag, ""))
	return priv.Public()
}

// checkChainBlocks covers the remaining-blocks MUST. It returns the parsed
// chain only when every block is a parseable certificate; the later chain
// checks would otherwise be judging a chain with holes in it. first is the
// 1-based file position of blocks[0], for the details.
func checkChainBlocks(r *report.Report, tag string, blocks []*pem.Block, first int) []*x509.Certificate {
	var (
		certs    []*x509.Certificate
		problems []string
	)
	for i, b := range blocks {
		pos := i + first
		if b.Type != typeCertificate {
			problems = append(problems, fmt.Sprintf("block %d is %q", pos, b.Type))
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			problems = append(problems, fmt.Sprintf("block %d: %v", pos, err))
			continue
		}
		certs = append(certs, c)
	}
	if len(problems) > 0 {
		r.Fail(spec.FSDCredentialBundleCertificates, annotate(tag, strings.Join(problems, "; ")))
		return nil
	}
	r.Pass(spec.FSDCredentialBundleCertificates, annotate(tag, fmt.Sprintf("%d certificate(s)", len(certs))))
	return certs
}

// checkChainOrder checks leaf-to-root order by issuedBy: each certificate's
// issuer must be the next one's subject, key identifiers agreeing when both
// are present. Signatures are not verified — that would be path validation,
// which is the application's job.
func checkChainOrder(r *report.Report, tag string, certs []*x509.Certificate) {
	for i := 0; i+1 < len(certs); i++ {
		if !issuedBy(certs[i], certs[i+1]) {
			r.Fail(spec.FSDCredentialBundleChainOrder, annotate(tag,
				fmt.Sprintf("certificate %d's issuer %q / authority key ID %x is not certificate %d's subject %q / key ID %x",
					i+1, certs[i].Issuer, certs[i].AuthorityKeyId, i+2, certs[i+1].Subject, certs[i+1].SubjectKeyId)))
			return
		}
	}
	r.Pass(spec.FSDCredentialBundleChainOrder, annotate(tag, ""))
}

func checkLeafKey(r *report.Report, tag string, leaf *x509.Certificate, key crypto.PublicKey) {
	pub, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(key) {
		r.Fail(spec.FSDCredentialBundleLeafKey, annotate(tag, "leaf public key does not match the PRIVATE KEY block"))
		return
	}
	r.Pass(spec.FSDCredentialBundleLeafKey, annotate(tag, ""))
}

// checkLeafSVID runs the X509-SVID.md sweep on a scratch report and folds the
// outcome into one SHOULD assertion, so the leaf's MUST failures surface as a
// warning here instead of failing the folder. A CA leaf is caught first:
// x509svid would check it as a signing certificate and could pass it.
func checkLeafSVID(r *report.Report, tag string, leaf *x509.Certificate) {
	if leaf.IsCA {
		r.Fail(spec.FSDCredentialBundleLeafSVID, annotate(tag, "leaf certificate has cA=true"))
		return
	}
	var sub report.Report
	x509svid.Check(&sub, leaf)
	var failed []string
	for _, a := range sub.Assertions {
		if a.Status == report.StatusFail {
			failed = append(failed, a.Clause.Spec+" "+a.Clause.Section+" "+a.Clause.Text)
		}
	}
	if len(failed) > 0 {
		r.Fail(spec.FSDCredentialBundleLeafSVID, annotate(tag,
			"violates "+strings.Join(failed, "; ")+" (run scc x509-svid on the file for details)"))
		return
	}
	r.Pass(spec.FSDCredentialBundleLeafSVID, annotate(tag, ""))
}

// checkNoTrustAnchor flags a chain certificate that is self-signed, or that is
// byte-for-byte one of the folder's trust anchors. The second case catches
// the rarer intermediate-as-anchor setups §2.2 allows.
func checkNoTrustAnchor(r *report.Report, tag string, certs []*x509.Certificate, trustAnchors []*x509.Certificate) {
	for i, c := range certs {
		if ok, how := isSelfSigned(c); ok {
			r.Fail(spec.FSDCredentialBundleNoTrustAnchor, annotate(tag,
				fmt.Sprintf("certificate %d (%s) %s", i+1, c.Subject, how)))
			return
		}
		if slices.ContainsFunc(trustAnchors, c.Equal) {
			r.Fail(spec.FSDCredentialBundleNoTrustAnchor, annotate(tag,
				fmt.Sprintf("certificate %d (%s) is a trust anchor in this folder", i+1, c.Subject)))
			return
		}
	}
	r.Pass(spec.FSDCredentialBundleNoTrustAnchor, annotate(tag, ""))
}

// checkTrustBundle covers §2.2 for one file. The <trust-domain> part of the
// name gets the SPIFFE-ID.md trust domain sweep: the file name is how an
// application finds the bundle for a peer's trust domain (§3.2), so a name
// that is not a valid trust domain can never be looked up.
func checkTrustBundle(r *report.Report, tb trustBundle) {
	if tb.trustDomain == "" {
		r.Fail(spec.FSDTrustBundleName, tb.name+": empty <trust-domain>")
	} else {
		r.Pass(spec.FSDTrustBundleName, tb.name)
	}
	id.CheckTrustDomain(r, tb.name, tb.trustDomain)

	if tb.problem != "" {
		r.Fail(spec.FSDTrustBundleCertificates, tb.name+": "+tb.problem)
		return
	}
	if len(tb.raw) == 0 {
		r.Pass(spec.FSDTrustBundleCertificates, tb.name+": empty, redacted (§2.3)")
		return
	}
	blocks, interBlock := splitPEM(tb.raw)
	checkFileShape(r, tb.name, blocks, interBlock, typeCertificate)

	var (
		problems []string
		certs    int
	)
	for i, b := range blocks {
		if b.Type != typeCertificate {
			continue // reported by checkFileShape
		}
		certs++
		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			problems = append(problems, fmt.Sprintf("block %d: %v", i+1, err))
		}
	}
	switch {
	case certs == 0:
		r.Fail(spec.FSDTrustBundleCertificates, tb.name+": no CERTIFICATE blocks")
	case len(problems) > 0:
		r.Fail(spec.FSDTrustBundleCertificates, tb.name+": "+strings.Join(problems, "; "))
	default:
		r.Pass(spec.FSDTrustBundleCertificates, fmt.Sprintf("%s: %d certificate(s)", tb.name, certs))
	}
}

// checkOwnTrustBundle covers §2.2's bundle "for the workload's own trust
// domain", taken from the leaf's SPIFFE ID, and then §2.1's rule that the
// chain stops right below a trust anchor. The trust domain is read from the
// parsed URI's host rather than from a re-serialized string, so it is the one
// the certificate carries. An authority with a port or userinfo has no valid
// trust domain (SPIFFE-ID.md §2.1), so it is treated like a leaf with no
// SPIFFE ID rather than stripped down to a host that would look one up. When
// the own bundle cannot be identified, is missing, or holds no usable anchor,
// the chain is matched against every anchor in the folder instead, so the
// chain MUST is still evaluated.
func checkOwnTrustBundle(r *report.Report, chain []*x509.Certificate, trust []trustBundle) {
	leaf := chain[0]
	if len(leaf.URIs) != 1 || !ownTrustDomainUsable(leaf.URIs[0]) {
		// No trust domain to look up. The leaf being an SVID is only a
		// SHOULD, already warned on, so failing the own-bundle MUST here
		// would make that SHOULD fatal through the back door.
		checkChainComplete(r, chain, trust, "this folder")
		return
	}
	want := leaf.URIs[0].Hostname() + TrustBundleSuffix
	i := slices.IndexFunc(trust, func(tb trustBundle) bool { return tb.name == want })
	if i < 0 {
		r.Fail(spec.FSDOwnTrustBundle, want+" not found")
		checkChainComplete(r, chain, trust, "this folder")
		return
	}
	r.Pass(spec.FSDOwnTrustBundle, want)
	if len(anchors(trust[i:i+1])) == 0 {
		// Redacted or unparseable: nothing of its own to stop below.
		checkChainComplete(r, chain, trust, "this folder")
		return
	}
	checkChainComplete(r, chain, trust[i:i+1], want)
}

// ownTrustDomainUsable reports whether u's authority is a bare host that can
// name a trust bundle file.
func ownTrustDomainUsable(u *url.URL) bool {
	return u.Scheme == "spiffe" && u.User == nil && u.Port() == "" && u.Hostname() != ""
}

// checkChainComplete covers "It MUST stop at the certificate preceding the
// trust anchor": the last chain certificate must be issued by an anchor in
// bundles. Like checkChainOrder it matches names and key identifiers, not
// signatures. When every
// bundle in the folder is redacted or unparseable there is genuinely no input
// left to check against, so no assertion is made; checkTrustBundle reports the
// unparseable ones and the redactions.
func checkChainComplete(r *report.Report, chain []*x509.Certificate, bundles []trustBundle, where string) {
	ownAnchors := anchors(bundles)
	if len(ownAnchors) == 0 {
		return
	}
	last := chain[len(chain)-1]
	if ok, _ := isSelfSigned(last); ok {
		return // the chain carries its anchor; checkNoTrustAnchor failed it
	}
	if slices.ContainsFunc(ownAnchors, func(a *x509.Certificate) bool {
		return issuedBy(last, a)
	}) {
		r.Pass(spec.FSDCredentialBundleChainComplete, annotate(CredentialBundleName, ""))
		return
	}
	r.Fail(spec.FSDCredentialBundleChainComplete, annotate(CredentialBundleName,
		fmt.Sprintf("last certificate's issuer %q is not an anchor in %s", last.Issuer, where)))
}

// checkFileShape covers the three MUST NOTs §2.1 and §2.2 each list for their
// file.
func checkFileShape(r *report.Report, tag string, blocks []*pem.Block, interBlock bool, allowed ...string) {
	var other, headed []string
	for i, b := range blocks {
		if !slices.Contains(allowed, b.Type) {
			other = append(other, fmt.Sprintf("block %d is %q", i+1, b.Type))
		}
		if len(b.Headers) > 0 {
			headed = append(headed, fmt.Sprintf("block %d", i+1))
		}
	}

	if len(other) > 0 {
		r.Fail(spec.FSDNoOtherBlockTypes, annotate(tag, strings.Join(other, "; ")))
	} else {
		r.Pass(spec.FSDNoOtherBlockTypes, annotate(tag, ""))
	}
	if interBlock {
		r.Fail(spec.FSDNoInterBlockData, annotate(tag, "non-whitespace data outside PEM blocks"))
	} else {
		r.Pass(spec.FSDNoInterBlockData, annotate(tag, ""))
	}
	if len(headed) > 0 {
		r.Fail(spec.FSDNoPEMHeaders, annotate(tag, strings.Join(headed, ", ")+" carry PEM headers"))
	} else {
		r.Pass(spec.FSDNoPEMHeaders, annotate(tag, ""))
	}
}

var pemBegin = []byte("-----BEGIN ")

// splitPEM decodes every PEM block in raw and reports whether anything other
// than whitespace sits outside them. encoding/pem silently skips such data —
// including a malformed block, which it steps over to reach the next one — so
// the gaps are measured here instead. Whitespace between blocks is not counted
// as data: the newline after an END line is how every PEM encoder ends a block.
func splitPEM(raw []byte) (blocks []*pem.Block, interBlock bool) {
	rest := raw
	for {
		i := bytes.Index(rest, pemBegin)
		if i < 0 {
			return blocks, interBlock || len(bytes.TrimSpace(rest)) > 0
		}
		if len(bytes.TrimSpace(rest[:i])) > 0 {
			interBlock = true
		}
		b, next := pem.Decode(rest[i:])
		if b == nil {
			return blocks, true
		}
		consumed := rest[i : len(rest)-len(next)]
		if bytes.Count(consumed, pemBegin) > 1 {
			interBlock = true
		}
		blocks = append(blocks, b)
		rest = next
	}
}

// isSelfSigned reports whether cert is self-signed: its issuer and subject
// match and its signature is not shown to be wrong. CheckSignature rather than
// CheckSignatureFrom: the latter also demands that the parent be a CA with
// keyCertSign, so a self-signed root lacking either would read as not
// self-signed and slip past the trust anchor MUST NOT. For the same reason a
// signature crypto/x509 refuses to judge (SHA-1, MD5, an algorithm it lacks)
// counts as self-signed: an old root is still the chain's anchor.
// The returned description says which of the two it was, for the detail.
func isSelfSigned(cert *x509.Certificate) (bool, string) {
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return false, ""
	}
	err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	var insecure x509.InsecureAlgorithmError
	switch {
	case err == nil:
		return true, "is self-signed"
	case errors.As(err, &insecure) || errors.Is(err, x509.ErrUnsupportedAlgorithm):
		return true, fmt.Sprintf("is self-issued (issuer = subject; %s signature not verifiable)", cert.SignatureAlgorithm)
	default:
		return false, ""
	}
}

// issuedBy reports whether c names a as its issuer: the issuer DN matches a's
// subject and, when both certificates carry key identifiers, c's authority key
// ID matches a's subject key ID. No signature is checked; that would be path
// validation.
func issuedBy(c, a *x509.Certificate) bool {
	if !bytes.Equal(c.RawIssuer, a.RawSubject) {
		return false
	}
	if len(c.AuthorityKeyId) > 0 && len(a.SubjectKeyId) > 0 {
		return bytes.Equal(c.AuthorityKeyId, a.SubjectKeyId)
	}
	return true
}

// annotate prefixes a detail with the file it came from, collapsing to
// whichever half is non-empty.
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
