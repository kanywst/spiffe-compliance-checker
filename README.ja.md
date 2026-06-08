<img src="./assets/logo-owl.png" align="right" width="160" alt="spiffe-compliance-checker logo" />

# spiffe-compliance-checker

[English](README.md) | **日本語**

[![ci](https://github.com/kanywst/spiffe-compliance-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/kanywst/spiffe-compliance-checker/actions/workflows/ci.yml)

![demo](./assets/demo.gif)

[SPIFFE](https://spiffe.io) の artifact を静的に検証する CLI。SPIFFE ID 文字列、X.509-SVID 証明書、JWT-SVID トークン、Trust Bundle のいずれかを `scc` に渡すと、[SPIFFE 仕様](https://github.com/spiffe/spiffe/tree/main/standards) の MUST / MUST NOT 句のうち何が満たされていて何が違反しているかを 1 行ずつ報告する。各行には仕様書名とセクション番号が付くので、落ちた assertion からそのまま仕様本文に飛んで根拠を確認できる。

SPIFFE は CNCF の仕様セットで、`spiffe://...` 形式の workload identity とそれを運ぶ SVID を定義している。SPIRE、Istio の mTLS、Cilium の mutual auth、社内製の実装などが SPIFFE 準拠を名乗っている。仕様は [spiffe/spiffe](https://github.com/spiffe/spiffe) の 8 本の markdown に分散しているが、公式の conformance suite は存在しない。`scc` はその空白のうち「外から artifact だけ見て検証できる範囲」をカバーする。Workload attestation、鍵ローテーション、Workload API endpoint の振る舞い、特定 bundle に対する署名検証などの動的な側面はスコープ外。

## インストール

どれを使っても同じ `scc` バイナリが PATH に入る。

```bash
# Homebrew (macOS + Linux、prebuilt バイナリ)
brew install kanywst/tap/spiffe-compliance-checker

# go install (Go 1.26+ ある環境ならどこでも)
go install github.com/kanywst/spiffe-compliance-checker/cmd/scc@latest

# Prebuilt アーカイブを直接ダウンロード
# https://github.com/kanywst/spiffe-compliance-checker/releases
```

CLI は色付き出力に [`charm.land/lipgloss/v2`](https://github.com/charmbracelet/lipgloss)、TTY 検出に `golang.org/x/term` を使う。他のランタイム依存なし。

## 使い方

```text
scc id        <spiffe-id-string>
scc x509-svid <cert.pem | cert.der>
scc jwt-svid  <token>
scc bundle    <bundle.json>
```

各サブコマンドは assertion 1 件につき 1 行を出力する。MUST 句が 1 つでも落ちれば exit code は 1、それ以外は 0。SHOULD 違反は `WARN` として表示され exit code には影響しない。色は stdout が TTY かつ `NO_COLOR` が未設定のときだけ ON になるので、script や CI ログでも同じバイナリが安全に使える。

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

## カバレッジ

| 仕様                                  | `scc` がチェックするもの                                                                            |
| ------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `SPIFFE-ID.md`                        | scheme、trust domain の charset / 長さ / case、path segment、URI 全長、query / fragment 不在        |
| `X509-SVID.md`                        | URI SAN 個数、leaf / signing の Basic Constraints、Key Usage 各 flag、EKU、leaf SPIFFE ID 規約      |
| `JWT-SVID.md`                         | `alg` whitelist、JWS Compact Serialization、`sub` / `aud` / `exp` の存在、`sub` の SPIFFE ID 妥当性 |
| `SPIFFE_Trust_Domain_and_Bundle.md`   | JWKS shape、key ごとの `kty` / `use`、`spiffe_sequence` / `spiffe_refresh_hint`、x509 の `x5c`      |

MUST 句は `spiffe/spiffe` main ブランチ 2026-05 時点を出典としている。

## 関連プロジェクト

- [spiffe/spiffe](https://github.com/spiffe/spiffe) — このツールが検証対象とする仕様セット
- [spiffe/go-spiffe](https://github.com/spiffe/go-spiffe) — SVID を「形だけ確認する」のではなく「実際に消費する」プロダクションコードで使う Go ライブラリ
- [spiffe/spire](https://github.com/spiffe/spire) — Workload API の参照実装

## ライセンス

Apache-2.0。詳細は `LICENSE`。
