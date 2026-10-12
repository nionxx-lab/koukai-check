# 公開前監査と公開リポジトリへの移行設計

実施日: 2026-10-11
範囲: koukai-check 自身を一般公開してよいかの監査と、専用の公開リポジトリへの移行設計。**MVP の診断機能は凍結済み**（新しい診断機能は追加しない）。このフェーズでは公開・リポジトリ作成・Release の公開・コード署名の購入は行っていない。

## 1. 公開前監査の結果

値そのものは記載しない。

| 項目 | 方法 | 結果 |
|---|---|---|
| 秘密情報・API キー・トークンの直書き | koukai-check 自身で自己チェック ＋ 一般的な形（AWS・Stripe・GitHub・Anthropic・OpenAI・Supabase・Slack・Google・JWT・パスワードの代入）で全ファイルを検索 | **なし**。見つかった形はすべてテストの見本の値（`TEST_ONLY`・`your_key_here`・署名部 `x` の JWT など）か、テスト実行時に乱数で作る値 |
| Git の履歴に残った秘密情報 | 自己チェック（28 コミット・220 版）＋ 全コミットに同じ検索 | **なし**（テストの見本の値だけ。22 種類の値を、テスト用の語・テンプレート・ランダムさで分類） |
| 秘密鍵・サービスアカウント鍵 | 自己チェック ＋ `BEGIN … PRIVATE KEY` の検索 | **なし**。該当は検出コード・ドキュメントの説明・テスト（鍵はテスト実行時に生成） |
| テストの値が本物らしく見えないか | 上の分類 | 本物らしい固定値はない。ただし GitHub の secret scanning（push protection）が、形だけで `sk_live_…` などの見本を止める可能性はある（下の 2.） |
| 作者 PC の絶対パス・ユーザー名 | 全ファイル・全履歴の検索 | **あり（要修正）**：`docs/fix-root-detection.md`（2 か所）・`test/scan.test.ts`（冒頭のコメント）に、作者の Windows のユーザー名を含むフォルダのパス |
| 別の非公開プロジェクトの名前 | 検索 | **あり（要修正）**：`test/scan.test.ts`（6 か所）・`docs/fix-root-detection.md`・`docs/secret-name-claude-code-oauth-token.md` に、作者の別プロジェクトのフォルダ名 |
| 一時ファイル・test-results・スクリーンショット・ローカル専用設定・`.env*` | 追跡中のファイル・全履歴の名前で検索 | **なし** |
| GitHub Actions の秘密情報 | ワークフローの確認 | **なし**。使うのは `github.token` だけ。権限はジョブごとに最小（既定 `contents: read`）。`pull_request_target` は使っていない |
| 不要な巨大バイナリ | 追跡中のファイル・履歴の大きさ | 現在の追跡中のファイルにはない（最大でも 200KB 未満）。**履歴には 80〜89MB の exe が 11 版**（圧縮後のリポジトリ全体で約 101MB） |
| 作者しか使えない設定 | 検索 | `package.json` の `repository`・`docs/release-windows.md` の検証コマンドが、現在の非公開の開発リポジトリを指している（公開前の整理で、公開リポジトリ koukai-check に合わせた）。公開リポジトリへの移行時に書き換える |
| 親リポジトリの無関係な内容 | 一覧 | `docs/` に市場調査などの社内向け文書が 3 件。公開リポジトリには含めない |

### 監査で見つけて直したこと

- **Git の履歴のチェックが通信しうる場合があった**：一部だけを取得したリポジトリ（partial clone）では、手元にないファイルの版を git が自動でリモートから取りに行く。`GIT_NO_LAZY_FETCH=1` で止め、さらに partial clone と分かったら履歴を読まないようにした（テストで、実行の前後でオブジェクトが増えないことを確認）。
- 静的監査のテストが、正規表現の `.exec(` を子プロセスの `exec(` と取り違えていた。子プロセスは `spawnSync` だけを取り込んでいることを確かめる形に直した。
- README を、初心者向けに「できること・しないこと・通信・Git がない場合」を明記した内容に書き直した。

## 2. 公開前に直す必要がある点

| 優先 | 内容 |
|---|---|
| 必須 | 作者のユーザー名を含むパス・別プロジェクト名を、一般的な例（`C:\Users\あなた\Desktop\my-app` など）に置き換える（`docs/fix-root-detection.md`・`test/scan.test.ts`・`docs/secret-name-claude-code-oauth-token.md`） |
| 必須 | `package.json` の `repository`・ワークフロー（`koukai-check/` を前提にしたパス）・`docs/release-windows.md` のリポジトリ名を、公開リポジトリに合わせる |
| 必須 | **`npx koukai-check` の扱いを決める**。`package.json` は `"private": true` で npm に公開していないため、README の macOS / Linux の手順（`npx`）は今のままでは動かない。npm に公開するか、README を「ソースから `npm ci && npm start`」に変えるかを決める |
| 必須 | 公開リポジトリでは artifact attestation が使える（Free プランでも公開リポジトリは可）。最初の Release の前に、`gh attestation verify` が通ることを確かめる |
| 推奨 | 開発の経緯の文書（`docs/phase*.md` など）のうち、利用者に不要で、社内の運用（Owner・PR の運用など）に触れるものは、公開リポジトリに入れないか `docs/dev-notes/` にまとめる。設計と根拠の文書（`secret-definitions.md`・`release-windows.md`・`phase4.13-git-history.md` など）は残す |
| 推奨 | `.gitattributes` で改行を固定する（Windows の作業コピーで CRLF になり、exe に入る `app.manifest` の中身が OS で変わるため） |
| 推奨 | 公開リポジトリへの最初の push で、GitHub の push protection がテストの見本の値（`sk_live_…` の形）を止めないか確かめる。止まる場合は、見本の値を、形の判定で確実にテスト用と分かる別の書き方にする（許可の設定で回避するより、値を変える） |

## 3. 専用の公開リポジトリへの移行方式

| | A. いまのサブフォルダの履歴を保ったまま分離（`git filter-repo --subdirectory-filter` など） | B. いまの完成状態を最初のコミットにして新しく作る |
|---|---|---|
| 公開されるもの | koukai-check の 28 コミットすべて：**80〜89MB の exe 11 版**・旧実装・開発途中のテストの値・作者のパスを含む文書 | 完成状態のソースだけ |
| exe の履歴を消すには | 履歴の書き換えがさらに必要（結局、元の履歴とは別物になる） | 不要 |
| 作者のパス・別プロジェクト名 | 過去のコミットに残る（消すには書き換え） | 修正後の状態から始めるので残らない |
| 親リポジトリの無関係な内容 | サブフォルダだけを取り出せば含まれない | 含まれない |
| 開発の経緯の透明性 | 高い | 低い（ただし、経緯は設計文書・CHANGELOG で説明できる） |
| 大きさ | 圧縮後で約 100MB（exe を消さない場合） | 1MB 未満 |
| 利用者が検証するもの | 公開リポジトリのソース・Actions のビルド・SHA256・provenance（どちらでも同じ） | 同じ |

**推奨：B（完成状態を最初のコミットにして新しく作る）。**

- このツールの信頼性は「公開しているソースから、公開している CI でビルドし、SHA256 と provenance で結び付けた exe を配る」ことで示す。過去の開発中の exe・旧実装・途中のテストの値は、利用者の検証には使わず、公開する必要がない。
- 過去の 89MB の exe 群は、それ自体を配布物として検証できる手段（CI のビルド・provenance）がなく、公開すると「どれが正しい exe か」を混乱させる。
- 作者のパスなどを履歴に残さないために、どのみち A でも書き換えが必要になる。B は書き換えではなく、修正後の状態から始めるだけ。
- **隠蔽にしないため**：最初のコミットのメッセージと CHANGELOG に「非公開の開発リポジトリから、Phase 4.13（MVP 凍結）の状態を移した」こと、移行元のコミット（`5e97a0f` 以降の最終コミット）を書く。設計文書（判定の根拠・意図的に検出しないもの・CI で見つかって直したこと）は公開リポジトリに含める。

移行の手順（次フェーズ）：

1. この非公開リポジトリで、2. の「必須」を直す
2. 新しい公開リポジトリ（例：`koukai-check`）を作り、`koukai-check/` の中身をルートに置いて最初のコミット（`.github/workflows/` もルートへ。パスを直す）
3. 公開リポジトリで PR の CI（テスト・ビルド）が通ることを確かめる
4. テスト用タグ（`koukai-check-ci-test-*`）で、Release の下書き・provenance（`gh attestation verify`）・SHA256 を確かめ、テスト用の下書きとタグを消す
5. 本番用タグ（`koukai-check-v0.1.0`）で下書きを作り、Owner が `docs/release-windows.md` の確認項目を確かめてから公開する

## 4. 公開時に必要なファイル

| ファイル | 状態 | 対応 |
|---|---|---|
| `README.md` | **更新済み**（できること・しないこと・通信・Git がない場合・確かめ方） | 3. の移行時にリポジトリ名・npx の扱いを直す |
| `LICENSE` | PolyForm Shield License 1.0.0（公式の本文・Required Notice: nionxx-lab）に変更済み | ライセンスの方針に従って MIT から変更（Strict は非商用の制限が製品の目的と合わないため不採用。公開リポジトリには以前の表記の履歴を持ち込まない） |
| `SECURITY.md` | **ない（必要）** | 脆弱性の報告方法（GitHub の private vulnerability reporting を有効にして案内）・対象範囲・対応の目安・報酬なし を書く |
| `CONTRIBUTING.md` | ない | 短く必要：MVP は凍結中で新しい診断機能の PR は受け付けない／誤検知・見逃し・不具合の報告は歓迎／秘密の値を Issue に貼らないこと |
| `PRIVACY.md` | README の「プライバシー」で説明済み | Release ページ・アプリからリンクしやすいよう、README の同じ内容を `PRIVACY.md` にも置くとよい |
| `THIRD-PARTY-NOTICES.txt` | ビルドで作り、Release に添付 | このままでよい（Node.js・WebView2 SDK のライセンス） |
| GitHub Actions のワークフロー | あり | 公開リポジトリのルートに置き、パスを直す。公開リポジトリでは attestation が自動で付く |
| Release の手順 | `docs/release-windows.md` | リポジトリ名を直す |
| SHA256 | `SHA256SUMS.txt`（添付ファイルすべて・ソースのコミット） | このままでよい |
| build provenance | ワークフローに実装済み（公開リポジトリでだけ動く） | 公開後の最初の Release で確かめる |
| `CHANGELOG.md` | ない | 推奨：移行元・Phase ごとの要点・MVP 凍結 |
| `.gitattributes` | ない | 推奨（改行の固定） |

## 5. 実行時の通信先

コード全体（`src/`・`native/windows-host/host.cpp`）から、通信し得る場所をすべて洗い出した。外部への通信は `src/supabase/client.ts` の `fetch` だけで、これは静的監査のテスト（`fetch` を使ってよいのは `client.ts` だけ・`node:https` などを使わない・テレメトリや解析の文字列がない・ソースに書かれた URL はすべて想定どおりのホスト）と、テスト中の通信の監視（network-guard）で確かめている。**作者独自のサーバーへの通信はない**（作者のサーバーの URL・ホストがコードにない）。

| 区分 | 通信先 | いつ | コード |
|---|---|---|---|
| 通常のローカルチェック | **なし**（`127.0.0.1` の画面のサーバーだけ。外部へは出ない） | フォルダを選んだとき | `src/app/server.ts`・`src/detect/*` |
| Git の履歴のチェック | **なし**（読み取りの git コマンドだけ。`GIT_NO_LAZY_FETCH=1`、partial clone は読まない） | フォルダを選んだとき | `src/detect/git-history.ts` |
| Supabase のオンラインチェック | `https://api.supabase.com`（固定。環境変数などで変えられない。リダイレクトは追わない） | 利用者が「Supabase のチェックを始める」でトークンを入れたとき | `src/supabase/client.ts` |
| 公式ドキュメントをブラウザで開く | `supabase.com`（とそのサブドメイン）・`firebase.google.com`・`docs.expo.dev`・`nextjs.org` の https だけ | 利用者がリンクを押したとき（既定のブラウザで開く。アプリ自体は通信しない） | `src/shared/url.ts`（許可するホストの一覧）・`host.cpp`（https だけ） |
| WebView2 ランタイムの入手案内 | `developer.microsoft.com` | WebView2 がない PC で、利用者が「はい」を押したとき（既定のブラウザで開く） | `host.cpp` |
| WebView2 自身の Windows 側の通信 | Microsoft（WebView2 ランタイムの更新・Windows の診断データの設定に従う送信） | Windows 側の動き。アプリからは止められない。**診断内容・フォルダの中身は含まれない**。SmartScreen による URL の評価は、表示するのが `127.0.0.1` だけのため無効にしている | `host.cpp`（`IsReputationCheckingRequired = FALSE`） |
| 開発者向けの `npx` | npm のレジストリ | `npx` がパッケージを取得するとき（アプリの外。npm に公開した場合だけ） | — |

## 6. 信頼性を利用者にどう説明するか

「信じてください」ではなく、**利用者が自分で確かめられる**形で示す。

1. **ソースを公開する**：通信するのは `src/supabase/client.ts` の1か所だけ、と README から読める場所を示す
2. **配る exe と公開ソースを結び付ける**：GitHub Actions でビルドし、`BUILD-INFO.txt`（ソースのコミット・Actions の実行）・`SHA256SUMS.txt`・build provenance（`gh attestation verify`）を付ける。exe はリポジトリにコミットしない
3. **テストで約束を守っていることを示す**：「外部通信は Supabase の1か所だけ」「値を画面・ログ・HTML に出さない」「ファイル・Git の履歴を書き換えない」をテスト・静的監査で確かめ、CI で毎回実行している
4. **オフラインで試せる**：ネットワークを切っても、Supabase 以外のチェックはすべて動く（README に表で記載）
5. **できないことを先に書く**：「すべての問題は見つけられない」「問題が表示されないことは安全の保証ではない」「Firebase はこの PC のルールファイルだけ」「Git がなければ履歴は見ない」を README・画面の両方に書く
6. **アカウント・広告・テレメトリがない**：収益化や利用状況の収集の仕組みがコードにない

## 7. コード署名

**今回は購入・実行していない。** 現状の署名のない exe の見え方と、次フェーズの候補を整理する。

### 署名がない exe の見え方

- ブラウザでダウンロードしたファイル（「インターネットから取得した」印＝Mark of the Web が付く）を初めて実行すると、Microsoft Defender SmartScreen が「**Windows によって PC が保護されました**」と表示し、「実行」ボタンが隠れる。「詳細情報」を押すと、アプリ名と「発行元：**不明な発行元**」が表示され、「実行」を押せる（README・はじめにお読みくださいで案内済み）
- ブラウザ（Edge など）のダウンロードでも「一般的にダウンロードされていません」などの警告が出ることがある
- exe は管理者の権限を求めない（`asInvoker`）ため、UAC の確認画面は出ない
- ファイルのプロパティに「デジタル署名」のタブがない
- SmartScreen の評価（レピュテーション）は、ダウンロードの実績で少しずつ付く。**署名がない場合はファイルの SHA256 ごと**なので、新しい版を出すたびに初めからになる

### 署名する場合（次フェーズの候補）

| | 内容 |
|---|---|
| メリット | 「不明な発行元」ではなく発行元の名前が出る。改ざんされていないことを Windows が確かめられる。SmartScreen の評価が、ファイルごとではなく証明書（発行元）にも積み上がり、版を重ねても警告が出にくくなる（ただし初回から警告が消えるわけではない） |
| 注意 | 2024 年以降、EV 証明書でも SmartScreen の評価がすぐには付かなくなった（OV と同じく実績で積み上がる）。EV を選ぶ利点は小さい |
| 選択肢 1：Azure Artifact Signing（旧 Trusted Signing） | 月額 9.99 ドル（Basic）。ただし公開の証明書を**個人で使えるのは米国・カナダだけ**（組織は米国・カナダ・EU・英国）。日本の個人は現時点で対象外 |
| 選択肢 2：認証局の OV コード署名証明書 | 個人向けの OV を出す認証局もある。本人確認（身分証明など）が必要。2023 年以降、鍵はハードウェア（USB トークン・HSM）かクラウドの署名サービスに置く必要がある。費用は年あたり数万円程度から（認証局・期間で異なる。購入前に見積もる） |
| 必要な手続き | 本人確認・証明書の購入・鍵の保管方法の決定（GitHub Actions から署名するなら、クラウドの署名サービスが現実的）・ワークフローに署名の手順を追加（ビルド → 署名 → SHA256 → provenance の順） |

参考：[EV 証明書が SmartScreen の評価をすぐには与えなくなった件](https://www.todesktop.com/blog/posts/windows-apps-psa-ev-certs-do-not-grant-immediate-reputation-anymore)・[SmartScreen の評価の考え方](https://textslashplain.com/2024/11/15/best-practices-for-smartscreen-apprep/)・[Azure Artifact Signing](https://azure.microsoft.com/en-us/products/artifact-signing)

## 8. 一般公開までの残作業

1. 2. の「必須」を直す（作者のパス・別プロジェクト名・リポジトリ名・npx の扱い）
2. `SECURITY.md`・`CONTRIBUTING.md`・（推奨）`PRIVACY.md`・`CHANGELOG.md`・`.gitattributes` を用意する
3. 開発の経緯の文書のうち、公開リポジトリに入れるものを選ぶ
4. 公開リポジトリを作り（方式 B）、CI・テスト用タグでの Release の下書き・provenance・SHA256 を確かめる（テスト用は確かめたら消す）
5. Windows 10 / 11 の実機で、Release からダウンロードした exe を確かめる（SmartScreen の表示・`docs/release-windows.md` の確認項目）
6. Owner が本番用タグで作った下書きを確かめて公開する
7. （任意・別判断）コード署名・npm への公開
