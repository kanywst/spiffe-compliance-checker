<img src="./assets/logo-owl.png" align="right" width="160" alt="spiffe-compliance-checker logo" />

# spiffe-compliance-checker

[English](README.md) | **日本語**

[![ci](https://github.com/kanywst/spiffe-compliance-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/kanywst/spiffe-compliance-checker/actions/workflows/ci.yml)

![demo](./assets/demo.gif)

[SPIFFE](https://spiffe.io) の artifact を静的に検証する CLI。SPIFFE ID 文字列、X.509-SVID 証明書、JWT-SVID / WIT-SVID トークン、Trust Bundle、Bundle Map、Bundle Endpoint 設定のいずれかを `scc` に渡すと、[SPIFFE 仕様](https://github.com/spiffe/spiffe/tree/main/standards) の MUST / MUST NOT 句のうち何が満たされていて何が違反しているかを 1 行ずつ報告する。各行には仕様書名とセクション番号が付くので、落ちた assertion からそのまま仕様本文に飛んで根拠を確認できる。

SPIFFE は CNCF の仕様セットで、`spiffe://...` 形式の workload identity とそれを運ぶ SVID を定義している。SPIRE、Istio の mTLS、Cilium の mutual auth、社内製の実装などが SPIFFE 準拠を名乗っている。仕様は [spiffe/spiffe](https://github.com/spiffe/spiffe) の 11 本の markdown に分散しているが、公式の conformance suite は存在しない。`scc` はその空白のうち「外から artifact だけ見て検証できる範囲」をカバーする。Workload attestation、鍵ローテーション、Workload API endpoint の振る舞い、特定 bundle に対する署名検証などの動的な側面はスコープ外。

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

### リリースの検証

各リリースには archive ごとの SPDX 2.3 SBOM (`<archive>.tar.gz.sbom.json`) と、`checksums.txt` に対する keyless [cosign](https://github.com/sigstore/cosign) 署名が Sigstore bundle (`checksums.txt.sigstore.json`) として付く。keyless なので取得すべき公開鍵は存在しない。署名者の identity は release workflow そのもので、Sigstore の透明性ログに記録されている。

```bash
# 1. checksums.txt がこのリポジトリの release workflow で署名されたことを検証する
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/kanywst/spiffe-compliance-checker/\.github/workflows/release\.yml@refs/tags/v'

# 2. 信頼できるようになった checksum リストと archive を突き合わせる
sha256sum --check --ignore-missing checksums.txt   # macOS は shasum -a 256 -c
```

## 使い方

```text
scc id         [--format text|json|sarif] <spiffe-id-string>
scc x509-svid  [--format text|json|sarif] <cert.pem | cert.der>
scc jwt-svid   [--format text|json|sarif] <token>
scc wit-svid   [--format text|json|sarif] <token>
scc bundle     [--format text|json|sarif] <bundle.json>
scc bundle-map [--format text|json|sarif] <bundle-map.json>
scc federation [--format text|json|sarif] --url <url> --profile <profile> --trust-domain <name>
               [--endpoint-spiffe-id <id>] [--endpoint-bundle <bundle.json>]
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
| `SPIFFE_Trust_Domain_and_Bundle.md` §5 | bundle map: `trust_domains` の存在、trust domain 名の妥当性と一意性、内包する各 bundle、`spiffe_refresh_hint` の省略 |
| `SPIFFE_Federation.md` §5             | bundle endpoint 設定: 必須 3 パラメータ、profile 種別、endpoint URL の scheme と userinfo、profile 固有パラメータ、bootstrap bundle |

MUST 句は `spiffe/spiffe` main ブランチの commit [`dc4e9d9`](https://github.com/spiffe/spiffe/commit/dc4e9d9) (2026-08-03) を出典としている。

### WIT-SVID について

[WIT-SVID](https://github.com/spiffe/spiffe/blob/main/standards/WIT-SVID.md) は 2026 年 7 月に spec set へ追加された 3 つ目の SVID 型。IETF WIMSE の Workload Identity Token を SPIFFE 向けにサブプロファイル化したもので、`cnf` claim に載せた workload の公開鍵をその SPIFFE ID に束ねる JWS 署名付き JWT。JWT-SVID と違って bearer token ではないため規約がいくつも反転する。一番わかりやすいのは `aud` で、JWT-SVID では必須、WIT-SVID では禁止。

`scc` が見るのはトークンの形だけ。WIT-SVID の提示時に必ず伴う proof of possession は runtime の話なのでスコープ外、署名検証も同様。

`WIT-SVID.md` は `spiffe/spiffe` 上で **Stability: Incubating** に分類されている。破壊的変更は避けられるが、実装からのフィードバック次第では入りうる、という段階。他の 3 本は Stable。つまり WIT-SVID 関連の句は今後動く可能性が他より高い。

trust bundle 側では WIT の署名鍵が `use` を `wit-svid` にした JWK entry として公開される (`WIT-SVID.md` §6.1)。`scc bundle` は `x509-svid` / `jwt-svid` に加えてこの値を受理し、該当 entry に `kid` を要求し、鍵付き entry 間で `kid` が衝突していないかを検査する。

### Bundle Map について

[SPIFFE Bundle Map](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#5-spiffe-bundle-map) (`SPIFFE_Trust_Domain_and_Bundle.md` §5) は trust domain 名をキーに bundle を並べた `trust_domains` オブジェクト。`scc bundle-map` は内包する各 bundle に対して `scc bundle` と同じ検査を丸ごと走らせ、どの trust domain 由来の assertion かを各行に明示した上で、map 自身の句を上乗せする。

- `trust_domains` は MUST で必須。ただし空でもよい。
- 各キーは有効な trust domain 名でなければならない。§5.1.1 がその判断を `SPIFFE-ID.md` §2 に委ねているので、SPIFFE ID の authority を検査するのと同じ句をそのままキーに適用している。
- trust domain 名は一意でなければならない。ここは素直に JSON を unmarshal しただけでは検出できない唯一の句で、Go を含む多くのパーサは重複キーの最後のものを黙って採用してしまう。そのため `scc` は生バイト列を token レベルで走査し直している。§6.3 が理由を書いている通り、名前が重複すると誤った trust anchor で SVID が検証されうる。
- map の中の bundle は `spiffe_refresh_hint` を SHOULD で省略する。単体の bundle とは逆向きの要求で、refresh hint は map 全体に掛かるものだから。

`kid` の一意性は bundle 単位のままなので、別々の trust domain が同じ `kid` を使っていても衝突扱いにはならない。

### Federation について

[SPIFFE Federation](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md) は、ある trust domain が別の trust domain の trust bundle を手に入れるための仕組み。相手側が *bundle endpoint* に bundle を公開し、こちらの client がそれを取りに行く。この仕様のほとんどは runtime の話 — TLS ハンドシェイク、証明書検証、HTTP GET、リダイレクト追従 — なのでスコープ外。`scc federation` が見るのは接続が始まる前に存在しているもの、つまり **bundle endpoint 設定** そのもの。§5.1 が「bundle を取得する前に client が持っていなければならない」と定めているパラメータ群。

仕様はそのパラメータを定義しているが、シリアライズ形式は定義していない。だから `scc federation` はファイルではなくフラグを取る。設定ファイル形式を勝手に決めれば、仕様が一度も規定していない shape を検査することになってしまう。

```bash
# Figure 4 の例: self-serving でない https_spiffe endpoint
scc federation \
  --url 'https://example.com/production/bundle.json' \
  --profile https_spiffe \
  --trust-domain prod.example.com \
  --endpoint-spiffe-id 'spiffe://example.com/spiffe-bundle-server'
```

チェックする内容:

- §5.1 の 3 パラメータが揃っているか。欠けている場合は usage error ではなく report 上の compliance 違反として出す。欠けていること自体が違反している要求そのものだから。
- trust domain 名が trust domain 名として妥当か。bundle map がキーに適用しているのと同じ `SPIFFE-ID.md` §2 の句を使う。
- profile が §5.2 の定義する 2 つのいずれかか。bundle の `use` が未知の値だった場合は §4.2.2 が「consumer は無視せよ」と書いているので SHOULD 止まりだが、profile にはその逃げ道がない。transport と認証方式そのものを指す名前なので、知らない profile では接続自体が成立しない。
- endpoint URL の scheme が `https` で、authority に userinfo が入っていないか (§5.2.1.1 と §5.2.2.1 が両 profile に対して同じ文言で要求している)。
- `https_spiffe` では endpoint server の SPIFFE ID が設定されているか (§5.2.2.2)。設定されていればその ID に `scc id` と同じ検査を丸ごと掛ける。
- `https_web` なのに `https_spiffe` 用のパラメータを持っている場合は WARN。§5.2.1.2 の MUST NOT が縛っているのは profile であって設定を書く運用者ではないので failure にはしない。ただし `https_web` に endpoint SPIFFE ID が付いているのはほぼ確実に profile の設定ミスで、client は気づかないまま Web PKI で endpoint を認証してしまう。
- **self-serving** な endpoint — 自分が配る bundle と同じ trust domain に自分の SPIFFE ID が属している endpoint — には、初回取得用の bootstrap bundle が要る。渡されていればそれを trust bundle として full の検査に掛ける。self-serving *でない* 場合、§5.2.2.2 は endpoint の trust domain を別途設定すると書いており、それは設定 1 件からは確認しようがないので、`scc` は空虚な結果を出さず黙る。

## 関連プロジェクト

- [spiffe/spiffe](https://github.com/spiffe/spiffe) — このツールが検証対象とする仕様セット
- [spiffe/go-spiffe](https://github.com/spiffe/go-spiffe) — SVID を「形だけ確認する」のではなく「実際に消費する」プロダクションコードで使う Go ライブラリ
- [spiffe/spire](https://github.com/spiffe/spire) — Workload API の参照実装

## ライセンス

Apache-2.0。詳細は `LICENSE`。
