# Phase 4 報告：公開前の安全性・配布品質・互換性の確認

実施日: 2026-10-07
範囲: 機能は追加していない。監査・テスト・安全性のための最小限の修正のみ。npm publish、GitHub Release、LPの公開（Phase 5）には着手していない。

---

## 1. 最終判定

> **2026-10-08 更新：実 API の確認が完了しました。**
> 利用者が Windows 実機（exe 版・専用ウィンドウ）で、実際の Supabase API を使って確認した：
> RLS 無効 → 🔴 危険 1件／RLS 有効・Policy なし → 🟠 要確認 1件／テスト用テーブルの削除 → すべて 0件。
> あわせて、Phase 4.7 の Windows 実機確認（起動・黒い画面なし・専用ウィンドウ・ブラウザを開かない・フォルダ選択が前面・診断の流れ・終了）も合格した。
>
> **更新後の判定**
> - **Windows の exe 版：公開可能**（Phase 5 の準備に進める）。exe 版ではトークンを画面のパスワード欄に貼り付けるため、ターミナルでの文字の隠し方（`manual-os-check.md`）は関係しない。
> - **npx（ターミナル）版：条件付き公開可能**。`manual-os-check.md` の、ターミナルでトークンが表示されないことの確認（macOS・Linux・Windows のターミナル）が残っている。
>
> 記録していない項目（エラー時の表示・元データの詳細など）は `manual-e2e-check.md` の「実施記録」に書いた。以下は 2026-10-07 時点の記録。

## （2026-10-07 時点）**条件付き公開可能：実API確認待ち**

- コード・配布物・ローカルでの安全性については、公開を止めるほどの問題は見つからなかった（見つかった問題はすべて修正済み）。
- 実際のSupabase APIを使ったEnd-to-Endの確認は、**未実施**。この環境からは `api.supabase.com` に接続できないため（ネットワークポリシーで遮断されている）。指示書 §21 のとおり、この状態では「公開可能」とは判定しない。
- あわせて、**本物の端末（TTY）でトークンが表示されないことの確認**と、**Windows / macOS での確認**も手動で行う必要がある（§10・§12）。

「公開可能」に変えるための条件：
- `docs/manual-e2e-check.md` の必須項目（3・4・5・7）が完了していること。
- `docs/manual-os-check.md` のうち、少なくとも Windows（PowerShell / Windows Terminal）、macOS（Terminal.app）、Linux の A・B・E・F・G が ✅ であること。

## 2. テスト総数と結果

`npm test`：**189件すべて通過**（Node 22.22.0）。
同じ189件を **Node 24.21.0 でも実行し、すべて通過**した。

| ファイル | 件数 | 内容 |
|---|---|---|
| client.test.ts | 19 | Phase 1（変更なし） |
| diagnostics.test.ts | 38 | Phase 2（免責文の変更に合わせて期待値を1か所更新） |
| report.test.ts | 35 | Phase 3（保存リンクの注意書きの文言変更に合わせて期待値を1か所更新） |
| cli.test.ts | 25 | Phase 3（変更なし） |
| **security.test.ts** | **57** | Phase 4：トークン入力、引数でのトークン拒否、SSRF、リンク、XSSファジング、サーバーへの攻撃、大量データ、API異常応答、コードの静的監査、ネットワークガード自体の確認、OS・端末の注意 |
| **e2e.test.ts** | **8** | Phase 4：実際のCLIプロセスでのトークン漏洩監査と、通信先の監査 |
| **package.test.ts** | **7** | Phase 4：`npm pack` の内容、依存パッケージ、package.json、shebang |

- **予期しない外部通信があればテストが失敗する仕組み**（`test/helpers/network-guard.ts`）：
  - すべてのテストプロセスと、テストが起動するCLIの子プロセスに読み込んでいる。
  - ループバックと、このPC自身のアドレス以外へのソケット接続や fetch を禁止する。
  - ガードが実際に外部への接続を止めることも、テストで確認している。

## 3. トークン漏洩の監査結果

識別用のトークン `SUPER_SECRET_TEST_TOKEN_123456`（`sbp_fc_…` / `sbp_…` の形）を使って確認した。**どこにも残っていなかった。**

| 確認した場所 | 方法 | 結果 |
|---|---|---|
| 標準出力・エラー出力 | E2E：対話入力、環境変数、Legacyトークン、401/403/429/500、接続エラー、入力途中の終了、`--token` 指定 | 含まれない |
| 配信HTML・保存HTML | E2E で取得して検索した | 含まれない（Legacyの警告は表示する） |
| スタックトレース | `KOUKAI_CHECK_DEBUG=1` でエラーを起こした | 表示されない。トークンも含まれない |
| 一時ファイル・HOME・作業ディレクトリ | E2E：空の HOME / TMPDIR / 作業ディレクトリで実行し、終了後に全ファイルを確認した | **ファイルが1つも作られない** |
| npmのログ・npxのキャッシュ | 手動：`npm pack` で作った tarball を、空の HOME で `npx --package <tgz> koukai-check` として実行した（ログレベル silly）。HOME以下をすべて検索した | 含まれない（作られたのは npm 自身のログとキャッシュだけ） |
| Supabaseへ送られた値 | テスト用の fetch の差し替えで、Authorization ヘッダーの長さと末尾を照合した（値そのものは記録していない） | 正しく送られている |

追加した対策：
- **`--token`、`--access-token`、`--pat`、`sbp_…` を引数で渡した場合は拒否する**（終了コード2）。値は表示しない。履歴に残った可能性があるので、トークンの削除と作り直しを案内する。
- 使えないオプションが指定された場合も、値を表示せずに拒否する（トークンが紛れている可能性があるため）。
- トークン入力の処理を純粋関数（`processSecretChunk`）に分けてテストした：
  - Backspace（0x7f / 0x08）、Ctrl+C、Ctrl+D、Ctrl+U
  - 矢印キーなどのエスケープシーケンス・制御文字の除去
  - 貼り付けと改行（CRLF / LF）、ゼロ幅文字の除去
  - 画面に何も出力しないこと
- 全角で入力されたトークンを半角に揃える（NFKC正規化）。
- 想定外の終了でも、端末を raw モードのまま残さない（`exit` のときに元に戻す）。
- **Windows の Git Bash（mintty）では、入力が表示される可能性があると警告する**（§13）。
- 案内文に「日本語入力（IME）はオフにして、手で打たずに貼り付けてください」を追加した。
- READMEの下書きで、対話入力を推奨とした。`SUPABASE_ACCESS_TOKEN=… npx` のようにコマンドに書く方法は避けるよう明記し、履歴に残らない設定方法（`read -rs`、`Read-Host -MaskInput`）を案内した。

## 4. 外部通信の監査結果

- **コードレビュー**：
  - `fetch` を使っているのは `supabase/client.ts` だけ。
  - `node:http` は `report/server.ts` だけで、待ち受けにしか使っていない。
  - `child_process` は `report/open-browser.ts` だけ。
  - `https`・`tls`・`dgram`・`dns`・`http2`、WebSocket、sendBeacon は使っていない。
  - Analytics・Telemetry・クラッシュレポート・AI APIへの通信はない。
  - これらはテストで静的に検査している。
- **ソース中のURL**：`api.supabase.com`、`supabase.com`（案内文）、`status.supabase.com`（案内文）、`nodejs.org`（案内文）、`127.0.0.1`、`localhost`、`github.com`（コメント内の出典）だけ。これもテストで検査している。
- **E2E**：診断1回で発生する外部通信は、`api.supabase.com` への1回だけだった。
- **ブラウザ**（Chromium）：レポートの表示・コピー・保存で発生した通信は、`127.0.0.1` への1回だけだった。保存したHTMLを `file://` で開いたときの通信は0件。
- **通信先の固定（SSRF対策）**：
  - 通信先は定数 `https://api.supabase.com` で、環境変数などから変える手段はない。
  - プロジェクトIDは `^[a-z]{20}$` だけを受け付ける。
  - 送信する直前にも、オリジンが固定値であることと、パスが `/v1/` で始まることを確認する（多重防御として追加した）。
  - **リダイレクトは追わない**（`redirect: 'error'`。追加した）。リダイレクト先のサーバーにトークンが届かないことを、テストで確認した。
  - `localhost`、`169.254.169.254`、`evil.example.com`、`//evil…`、`@evil…`、パストラバーサル、大文字、キリル文字など16種類の入力で、**通信そのものが行われない**ことを確認した。
  - URL入力からはIDだけを取り出す。Supabase以外のドメイン（`supabase.com.evil.example`、認証情報付きのURL、`169.254.169.254`、`localhost` など）は受け付けない（追加した）。

## 5. XSS / HTML安全性の結果

- **ファジング**：
  - 26種類の危険な文字列（`<script>`、`</script>`、`<img onerror>`、`">`、`'`、`` ` ``、`&`、`<`、`>`、`javascript:`、`data:`、`</textarea>`、`<base>`、`<meta refresh>`、双方向制御文字、改行入りの指示文など）を組み合わせた。
  - 400ケース × 外部から来るすべてのフィールド（name / title / level / facing / categories / description / detail / remediation / metadata.schema・name・type・entity・bucket_name・sensitive_columns / cache_key / observed_at / プロジェクトID）で、さらに単独のペイロードを各フィールドに入れて確認した。
  - 判定内容：
    - タグと属性が許可リストの中にある。
    - `<script>` は自分の nonce 付きの1つだけ。
    - `href` は `#d…`、`?download=1`、`https://*.supabase.com/…` だけ。
    - タグにならない `<` が残っていない。
    - textarea の閉じタグの数が対応している。
- **実際のブラウザ**（Chromium）：全フィールドに危険な文字列を入れたレポートを開いても、**スクリプトの実行0件**。注入されたタグ（img / svg / iframe / base / link）も0件で、`javascript:` や `data:` のリンクも作られなかった。
- **AI修正指示への指示文の紛れ込み（プロンプトインジェクション）**：
  - テーブル名などの改行や制御文字は空白に置き換え、双方向制御文字やゼロ幅文字は取り除き、200文字までに切り詰めてから文面に入れる（追加した）。
  - 公式の説明文も1行にまとめる。
  - 新しい見出しや指示行を作れないことを、ファジングで確認した。
- **リンク**：判定を `shared/url.ts` の `toSafeHelpUrl` に一本化した。
  - **https の Supabase ドメインだけ**をリンクにする（従来の「https なら何でも可」より厳しくした）。
  - `javascript:`、`data:`、`file:`、`http:`、`vbscript:`、認証情報付き、443以外のポート、2048文字を超えるURLは拒否する。
  - リンクにしなかったURLは、「技術的な詳細」の元データに文字として残るだけ。

## 6. ローカルサーバーの監査結果

| 項目 | 結果 |
|---|---|
| 待ち受けアドレス | `127.0.0.1` 固定（定数）。`0.0.0.0` や `::` はコード上に存在しない（テストで検査）。`[::1]` とLAN側のアドレスからは接続できない |
| URLのトークン部分 | 128ビットの乱数（`/r/<32桁の16進数>`）。起動ごとに変わる |
| Hostヘッダーの確認 | `127.0.0.1:<port>` と `localhost:<port>` 以外は403（Hostなしは Node.js 自体が400を返す）。`evil.example`、`127.0.0.1.evil.example`、`localhost.`、`[::1]`、`0.0.0.0` も拒否する |
| パストラバーサル・任意ファイルの読み取り | 17種類のパス（`../`、`%2e%2e`、`/etc/passwd`、`/package.json`、大文字、別の乱数など）はすべて404。**サーバーはファイルシステムを一切読まない**（メモリ上のHTMLだけを返す。コードで検査） |
| ダウンロード用の応答 | `?download=1` で同じHTMLを添付ファイルとして返すだけ。ファイル名は固定。それ以外のパラメータで別の内容を返さない |
| メソッド | GET / HEAD 以外（POST / PUT / DELETE / PATCH / OPTIONS / TRACE）は405 |
| 長いURL | 15,000文字でも落ちない（404 / 414 / 431 のいずれか） |
| 終了 | Ctrl+C、または最後の表示から30分（Phase 3 から変更なし） |

## 7. npm pack の内容

`npm pack --dry-run`：**31ファイル、パッケージサイズ 43.8kB（展開後 約147kB）**

```
LICENSE  README.md  package.json
samples/security-advisors.sample.json
dist/cli/{app,index,lifecycle,messages,project-ref,prompt,texts}.js
dist/diagnostics/{classify,index,resource}.js
dist/explanations/{definitions,prompt,template}.js
dist/report/{escape,html,open-browser,server,time}.js
dist/shared/url.js
dist/supabase/{client,errors,normalize,token,types,validate}.js
dist/types/{advisor,diagnostic}.js
```

- `files` で、公開するファイルを明示的に限定した。開発用の `dist/cli/preview.js` と `format.js` は除外している。
- 含まれていないことをテストで確認しているもの：
  - `.env`、`result.json`、ログ、スクリーンショット、`.git`、`.npmrc`
  - テスト・fixture、`docs/`、`src/`、`.ts`、`.map`、`tsconfig`、`dist-test`
- 同梱するすべてのファイルの中身に、トークンらしき文字列（`sbp_` で始まる16文字以上）、テスト用の秘密文字列、JWTが含まれないこともテストで確認している。
- `build` は毎回 `dist` を消してから作る（古いファイルの混入を防ぐ）。`prepack` で必ずビルドし直す。
- 利用者のインストール時に動くスクリプト（preinstall / install / postinstall / prepare）はない。

## 8. 依存関係

- `npm ls --omit=dev`：**(empty)**。実行時の依存パッケージは0個。
- 開発時の依存パッケージ：`typescript@5.9.3`、`@types/node@22.20.5`（とその依存の `undici-types`）だけ。配布物には含まれない。
- 依存パッケージは追加していない。

## 9. 対応する Node.js のバージョン

- **Node.js 22 以上**（`engines: ">=22"`）。
- 理由：
  - Node 20 は2026年4月にサポートが終了している。
  - Node 22（メンテナンスLTS）と Node 24（アクティブLTS）で全テストが通ることを確認した。
  - 使っている標準APIは、`fetch`、`AbortSignal.timeout`、`readline/promises` の `signal`、`http.Server.closeAllConnections`、`Web Streams` で、いずれも Node 22 以上で安定している。
- Node 20 で起動すると、「このツールには Node.js 22 以上が必要です（現在: 20.20.2）」と日本語で案内し、終了コード1で止まることを確認した。

## 10. OSごとの確認状況

| 項目 | Linux（この環境） | Windows | macOS |
|---|---|---|---|
| テスト全件（Node 22 / 24） | ✅ | 未確認 | 未確認 |
| `npx --package <tgz>` での起動 | ✅（診断の開始まで。この環境では接続が遮断） | 未確認 | 未確認 |
| トークンの非表示入力（本物のTTY） | **未確認**（この環境にTTYがない。処理関数のテストのみ） | 未確認 | 未確認 |
| IMEがオンのとき | — | **未確認**（手で入力すると変換窓に文字が出る可能性がある。案内で対処） | 未確認 |
| Git Bash（mintty） | — | 警告を出す（コードとテストのみ） | — |
| ブラウザの自動起動 | xdg-open（ヘッドレス環境のため未確認。開けない場合にURLを表示することは確認済み） | `cmd /c start "" <URL>`（未確認） | `open`（未確認） |
| クリップボード | ✅（Chromium、http://127.0.0.1 と file://） | 未確認 | 未確認（Safari） |
| Ctrl+C | ✅（SIGINT で終了コード0） | 未確認（Node は Windows でも SIGINT を扱う） | 未確認 |
| 一時ファイル・パス | ✅ 一時ファイルを作らない。`--from-file` は相対パス・絶対パスとも、Node の標準の解決に任せる | 未確認（日本語や空白を含むパス） | 未確認 |
| 日本語・絵文字 | ✅ | cmd.exe では絵文字が表示できない可能性がある | 未確認 |

手順は `docs/manual-os-check.md` にまとめた。

## 11. 実API E2Eの状況

**2026-10-08 に Windows 実機で実施済み**（結果は §1 と `docs/manual-e2e-check.md` の「実施記録」）。以下は 2026-10-07 時点の記録。

（2026-10-07 時点）**未実施。** 手順とチェックリストは `docs/manual-e2e-check.md` に作成した（テスト用プロジェクトの作成、Scoped PAT、Advisors: Read、tarballからの起動、RLS無効の表示、修正して再診断、Legacy PAT、無効なトークン、権限不足、observed_at、未確認の項目の有無、片付け）。

## 12. 公開前にユーザー側で行うべき手動確認

1. `docs/manual-e2e-check.md` の必須項目（3・4・5・7）。
2. `docs/manual-os-check.md` の A（貼り付けて表示されない）・B（Backspace）・E（Ctrl+C の後に端末が元に戻る）・F（ブラウザ）・G（コピー）を、少なくとも次の環境で：
   - Windows Terminal（PowerShell）
   - cmd.exe
   - macOS の Terminal.app
   - Linux
3. Windows で IME がオンのまま貼り付けた場合（C）と、手で入力した場合（D）の結果を記録する。
4. Safari・Firefox で、コピーと保存HTMLが動くか。
5. LICENSE の著作権者の表記（現在は「koukai-check contributors」）を確認する。
6. `package.json` の `repository` の確認（現在はこのリポジトリの `koukai-check/`）と、Phase 5 で `"private": true` を外すこと（誤って公開しないよう、現時点では残している）。

## 13. 残っている既知の制約

| 制約 | 影響 | 対応 |
|---|---|---|
| Windows の Git Bash（mintty）では、文字を隠した入力ができない | 入力したトークンが画面に表示される可能性がある | 起動時に警告を出し、PowerShell / Windows Terminal / `winpty` を案内する。READMEにも明記した |
| 日本語IMEがオンのまま手で入力すると、IMEの変換窓に文字が出ることがある | 画面を見られると、トークンの一部を見られる可能性がある | 「IMEをオフにして貼り付けて」と案内する。全角入力は半角に揃える |
| 環境変数のトークンは、同じユーザーの他のプロセスから見える可能性がある（OSの仕組み） | 低い | 対話入力を推奨する。READMEで安全な設定方法を案内した |
| ローカルサーバーに、同じPCの別のプロセスが接続を試みることはできる | URLの乱数（128ビット）を知らなければ読めない | 現状で十分と判断した |
| SSH接続先などリモートで実行すると、ブラウザで開けない | 127.0.0.1 は接続先のマシンを指すため | 制約として記録する。`--from-file` で手元で表示する手順は Phase 5 で案内を検討する |
| 指摘が2,000件を超える場合は打ち切る | 不完全である旨の注意を表示する | 通常のプロジェクトでは数十件程度のため、十分な上限と判断した |
| 応答が20MBを超える場合はエラーにする | 同上 | 同上 |
| 公式の解説リンクは supabase.com のドメインだけ | Supabaseが別ドメインのURLを返した場合はリンクにしない（元データには文字として残る） | 実APIの確認で、ドメインを確かめる |
| Security Advisor API は experimental 扱い | 仕様が変わるとエラーになる | 仕様変更の可能性を日本語で案内する（Phase 1 から変更なし） |
| 未確認の9項目 | APIが返すかどうか分からない | 実APIの確認待ち |
| npmでの名前 `koukai-check` | 2026-10-07時点で未使用（`npm view` は404） | 公開の直前にもう一度確認する。似た名前がある場合、npm 側で拒否されることがある |

## 14. Phase 5 へ進んでよいか

**次の条件を満たせば、進んでよい。**

- `docs/manual-e2e-check.md` の必須項目が完了し、重大な ❌ がない。
- `docs/manual-os-check.md` の主要な環境（§12-2）で、トークンが表示されないことを確認できている。

コードと配布物については、Phase 5 で公開作業を始められる状態になっている。ただし、上の手動確認が終わるまでは、npm publish を含む公開作業は行わないこと。

---

## Phase 4 で変更したファイル

```
src/cli/prompt.ts        トークン入力の処理を純粋関数に分割、制御文字やエスケープシーケンスの除去、
                         raw モードを確実に戻す処理、Git Bash の警告
src/cli/app.ts           引数でのトークン指定と不明なオプションを拒否、NFKC正規化、終了時に免責文を表示
src/cli/texts.ts         IMEの案内、引数でトークンを渡した場合の案内、Node.js のバージョン確認の文言
src/cli/index.ts         Node.js 22 未満で停止する
src/cli/project-ref.ts   URLの解析を URL オブジェクトで行い、Supabase以外のドメインを拒否
src/cli/messages.ts      429 の案内文
src/shared/url.ts（新規）  リンク化してよいURLの判定（https かつ supabase.com）
src/supabase/client.ts   送信前のオリジン確認、リダイレクトを追わない、応答サイズの上限、タイムアウトの注入（テスト用）
src/supabase/normalize.ts  指摘件数の上限（2,000件）、共通のURL判定を使う
src/diagnostics/classify.ts  名前の整形（sanitizeName）、免責文
src/explanations/template.ts, prompt.ts  プロンプト用の整形の強化（改行・双方向制御文字）
src/report/html.ts       表示する長さの上限、保存リンクの注意書きの文言、未知の項目の表示件数の上限
src/report/escape.ts     共通のURL判定を使う
src/types/advisor.ts     too_many を追加
test/security.test.ts, e2e.test.ts, package.test.ts, helpers/network-guard.ts, helpers/mock-supabase-fetch.ts（新規）
package.json             version 0.1.0、description、keywords、repository、engines >=22、files の限定、build で dist を消す、prepack
LICENSE（新規）、README.md（下書き・新規）
docs/manual-e2e-check.md, docs/manual-os-check.md, docs/phase4-release-readiness.md（新規）
```
