# spiffe-compliance-checker

**English** | [日本語](README.ja.md)

[![ci](https://github.com/0-draft/spiffe-compliance-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/0-draft/spiffe-compliance-checker/actions/workflows/ci.yml)

A static compliance checker for [SPIFFE](https://spiffe.io) artifacts. Pass `scc` a SPIFFE ID, an X.509-SVID certificate, a JWT-SVID token, or a trust bundle, and it tells you which MUST / MUST NOT clauses from the [SPIFFE spec](https://github.com/spiffe/spiffe/tree/main/standards) the artifact satisfies or violates. Every output line cites the source document and section so a failed check reads as a spec walkthrough.

SPIFFE is the CNCF spec set that defines `spiffe://...` workload identities and the SVIDs that carry them. It backs SPIRE, Istio's mTLS layer, Cilium's mutual auth, and many in-house implementations. The spec lives across eight markdown files in [spiffe/spiffe](https://github.com/spiffe/spiffe) and ships without an official conformance suite. `scc` covers the slice of compliance that is checkable from outside: the shape of the artifacts themselves. Runtime concerns (workload attestation, key rotation, Workload API endpoint behaviour, signature verification against a specific bundle) are out of scope.

## Install

```bash
go install github.com/0-draft/spiffe-compliance-checker/cmd/scc@latest
```

Requires Go 1.26 or newer. The CLI depends on [`charm.land/lipgloss/v2`](https://github.com/charmbracelet/lipgloss) for colored terminal output and `golang.org/x/term` for TTY detection. No other runtime dependencies.

## Usage

```text
scc id        <spiffe-id-string>
scc x509-svid <cert.pem | cert.der>
scc jwt-svid  <token>
scc bundle    <bundle.json>
```

Each subcommand prints one line per checked clause and exits non-zero if any MUST clause fails. SHOULD violations surface as `WARN` and do not change the exit code. Colors render only when stdout is a TTY and `NO_COLOR` is unset, so the same binary is safe in scripts and CI logs.

```text
$ scc id 'spiffe://Example.com/payments/web-fe'

scc id  spiffe://Example.com/payments/web-fe

  ✓ PASS  SPIFFE-ID.md §2    SPIFFE ID MUST NOT include query or fragment
  ✓ PASS  SPIFFE-ID.md §2    scheme MUST be "spiffe"
  ✓ PASS  SPIFFE-ID.md §2.1  trust domain MUST NOT be empty
  ✗ FAIL  SPIFFE-ID.md §2.1  trust domain MUST be lowercase
         → trust_domain="Example.com"
  ✗ FAIL  SPIFFE-ID.md §2.1  trust domain MUST contain only [a-z0-9.-_], no percent-encoding
         → trust_domain="Example.com"
  ✓ PASS  SPIFFE-ID.md §2.3  trust domain MUST be at most 255 bytes
  ✓ PASS  SPIFFE-ID.md §2.2  path segments MUST contain only [a-zA-Z0-9.-_]
  ✓ PASS  SPIFFE-ID.md §2.3  SPIFFE ID MUST be supported up to 2048 bytes

  ────────────────────────────────────
  11 passed  ·  2 failed  ·  0 warnings

$ echo $?
1
```

## Coverage

| Spec                                  | What `scc` checks                                                                                |
| ------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `SPIFFE-ID.md`                        | scheme, trust domain charset / length / case, path segments, total length, query / fragment      |
| `X509-SVID.md`                        | URI SAN count, leaf vs signing Basic Constraints, Key Usage flags, EKU, leaf SPIFFE ID rules     |
| `JWT-SVID.md`                         | `alg` whitelist, JWS Compact Serialization, `sub` / `aud` / `exp` presence, SPIFFE ID in `sub`   |
| `SPIFFE_Trust_Domain_and_Bundle.md`   | JWKS shape, `kty` / `use` per key, `spiffe_sequence` / `spiffe_refresh_hint`, `x5c` for x509     |

The MUST clauses are pulled directly from the `spiffe/spiffe` main branch as of 2026-05.

## Related

- [spiffe/spiffe](https://github.com/spiffe/spiffe) — the spec set this tool validates against
- [spiffe/go-spiffe](https://github.com/spiffe/go-spiffe) — the Go library to use when you need to *consume* SVIDs in production code, not just check their shape
- [spiffe/spire](https://github.com/spiffe/spire) — the reference implementation of the Workload API

## License

Apache-2.0. See `LICENSE`.
