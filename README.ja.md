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
scc id        [--format text|json|sarif] <spiffe-id-string>
scc x509-svid [--format text|json|sarif] <cert.pem | cert.der>
scc jwt-svid  [--format text|json|sarif] <token>
scc wit-svid  [--format text|json|sarif] <token>
scc bundle    [--format text|json|sarif] <bundle.json>
```

各サブコマンドは assertion 1 件につき 1 行を出力する。MUST 句が 1 つでも落ちれば exit code は 1、それ以外は 0。SHOULD 違反は `WARN` として表示され exit code には影響しない。色は stdout が TTY かつ `NO_COLOR` が未設定のときだけ ON になるので、script や CI ログでも同じバイナリが安全に使える。

### 出力フォーマット

`--format` で結果の出し方を選ぶ。exit code は 3 つとも同じなので、`json` / `sarif` でも CI のゲートに使える。

| フォーマット      | 用途                                                                            |
| ----------------- | ------------------------------------------------------------------------------- |
| `text` (デフォルト) | 人間向け。TTY なら色付き。                                                     |
| `json`            | 自動処理用の安定したオブジェクト (`jq` / script)。全 assertion と summary を含む。 |
| `sarif`           | [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning) など向けの SARIF 2.1.0。違反だけが result になる。 |

```bash
# pipeline を落としつつ結果を GitHub Code Scanning に上げる
scc x509-svid --format sarif leaf.pem > scc.sarif
```

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
| `WIT-SVID.md`                         | 必須の `kid` / `typ=wit+jwt` / `alg`、`cnf.jwk` の構造とアルゴリズム、禁止された `aud`、`nbf` / `iss` の規約 |
| `SPIFFE_Trust_Domain_and_Bundle.md`   | JWKS shape、key ごとの `kty` / `use`、`spiffe_sequence` / `spiffe_refresh_hint`、x509 の `x5c`、bundle 全体での `kid` 一意性 |

MUST 句は `spiffe/spiffe` main ブランチ 2026-08 時点 (spec commit `281c4b0`) を出典としている。

### WIT-SVID について

[WIT-SVID](https://github.com/spiffe/spiffe/blob/main/standards/WIT-SVID.md) は 2026 年 7 月に spec set へ追加された 3 つ目の SVID 型。IETF WIMSE の Workload Identity Token を SPIFFE 向けにサブプロファイル化したもので、`cnf` claim に載せた workload の公開鍵をその SPIFFE ID に束ねる JWS 署名付き JWT。JWT-SVID と違って bearer token ではないため規約がいくつも反転する。一番わかりやすいのは `aud` で、JWT-SVID では必須、WIT-SVID では禁止。

`scc` が見るのはトークンの形だけ。WIT-SVID の提示時に必ず伴う proof of possession は runtime の話なのでスコープ外、署名検証も同様。

`WIT-SVID.md` は `spiffe/spiffe` 上で **Stability: Incubating** に分類されている。破壊的変更は避けられるが、実装からのフィードバック次第では入りうる、という段階。他の 3 本は Stable。つまり WIT-SVID 関連の句は今後動く可能性が他より高い。

trust bundle 側では WIT の署名鍵が `use` を `wit-svid` にした JWK entry として公開される (`WIT-SVID.md` §6.1)。`scc bundle` は `x509-svid` / `jwt-svid` に加えてこの値を受理し、該当 entry に `kid` を要求し、鍵付き entry 間で `kid` が衝突していないかを検査する。

## 関連プロジェクト

- [spiffe/spiffe](https://github.com/spiffe/spiffe) — このツールが検証対象とする仕様セット
- [spiffe/go-spiffe](https://github.com/spiffe/go-spiffe) — SVID を「形だけ確認する」のではなく「実際に消費する」プロダクションコードで使う Go ライブラリ
- [spiffe/spire](https://github.com/spiffe/spire) — Workload API の参照実装

## ライセンス

Apache-2.0。詳細は `LICENSE`。
