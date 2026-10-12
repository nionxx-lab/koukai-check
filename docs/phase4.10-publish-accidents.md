# Phase 4.10：公開事故チェックの追加（Firebase ルール・秘密鍵・公開フォルダ・Stripe / AWS）

実施日: 2026-10-10
範囲: MVP で不足していた公開事故のうち、ローカルで誤検知を抑えて判定できる4項目を追加した。
Git 履歴のスキャン・認証なし API の意味解析・CORS・Stripe Webhook のロジック・依存パッケージの脆弱性・AI によるコード解析・Supabase の追加診断は、行っていない。

共通の方針（従来どおり）：値・鍵・ファイルの中身は、画面・ログ・HTML・診断結果に出さない。作者のサーバーへ送らない。参照だけ・ダミー・テスト用・公開してよいキーは数えない。判断できないものは危険扱いせず「判定しない」。

## 1. Firebase のセキュリティルール（`src/detect/firebase-rules.ts`）

対象：`firestore.rules`・`storage.rules`・`database.rules.json`、および `firebase.json` の `firestore.rules`・`storage.rules`・`database.rules` に書かれたファイル（選んだフォルダの中だけ）。

決まった形だけを見る。ルールの意味は解析しない。

| 形 | 全体（`/{document=**}`・`/{allPaths=**}`・RTDB の `rules` 直下） | 一部のパス |
|---|---|---|
| 誰でも許可（`if true`・条件なしの `allow`・RTDB の `true`） | 🔴 | 書き込み 🔴／読み取りだけ 🟠（公開してよいデータか確認） |
| 期限前のテストモード（`request.time < timestamp.date(…)`・`"now < ミリ秒"`） | 🔴 | 同上 |
| 期限切れのテストモード | 🟠（いまは拒否されるが、期限を延ばすだけで全開放に戻る） | 🟠 |
| ログインしていれば誰でも（`request.auth != null`・`"auth != null"`） | 🟠 | 数えない（ふつうの書き方） |
| `if false`・関数・`&&` などを含む条件 | 数えない（判定しない） | 数えない |

- コメントの中は見ない。読めないファイルは「判定していません」（📘）として出す。
- 🔴・🟠・✅ のどの項目にも「このPC内のルールファイルを確認した結果です。現在公開中の設定そのものとは限りません」と表示する。
- ルールファイルがなければ、従来の「Firebase コンソールで確認してください」の案内（📘）のまま。

## 2. 秘密鍵・サービスアカウント鍵（`src/detect/key-files.ts`）

ファイル名・拡張子では判定しない。読むファイルを選ぶのに拡張子（`.pem` `.key` `.p8` `.ppk` `.asc` `.txt`・`id_rsa` など）を使うだけで、危険かどうかは中身で決める。設定ファイル・ソースコードの中も同じように調べる。

| 中身 | 判定 |
|---|---|
| `-----BEGIN (RSA / EC / DSA / OPENSSH / ENCRYPTED) PRIVATE KEY-----` で、本体を base64 から戻すと鍵の形（ASN.1 の SEQUENCE・`openssh-key-v1`） | 秘密鍵 |
| JSON の `type` が `service_account` で、`private_key` が上の秘密鍵 | サービスアカウント鍵 |
| `-----BEGIN PGP PRIVATE KEY BLOCK-----`・PuTTY の鍵（`PuTTY-User-Key-File-`・`Private-Lines`） | 秘密鍵 |
| 証明書（`BEGIN CERTIFICATE`）・公開鍵（`BEGIN PUBLIC KEY`） | 数えない |
| テスト用の語を含む・本体が鍵の形をしていない | テスト用（数えない。折りたたみに場所だけ） |

重大度：Git で管理（tracked）・除外されていない（untracked）→ 🔴／Git なし → 🟠／`.gitignore` で除外 → 数えない（折りたたみで補足）。パスフレーズで暗号化された鍵は 🟠 にとどめる。GitHub App の秘密鍵の定義（名前つき）で見つけたファイルは重ねて出さない。

## 3. 公開フォルダ（`public/`・`static/`、直下の `firebase.json` の `hosting.public`）

公開フォルダの中は、`.gitignore` で除外していてもビルド・デプロイで Web に配信されうるため、Git の状態に関係なく判定する。

| 中身 | 判定 |
|---|---|
| 値の入った `.env`（見本の `.env.example` などは除く） | 🔴 |
| 秘密鍵・サービスアカウント鍵（2. と同じ判定） | 🔴（暗号化された鍵は 🟠） |
| SQLite のデータベース（先頭が `SQLite format 3\0`）・pg_dump のカスタム形式（`PGDMP`）・`-- PostgreSQL database dump` などの見出しのある `.sql` | 🔴 |
| 見出しはないが `CREATE TABLE` と `INSERT INTO` の両方がある `.sql` | 🟠（見本のデータの可能性） |
| Google の OAuth クライアントの JSON（`web` / `installed` の中に `client_secret`） | 🔴 |
| 既存の秘密情報の定義に一致する本物らしい値（`.txt`・`.html`・`.map` なども読む） | そのサービスの項目で 🔴（「公開フォルダ ○/ の中」と表示） |
| ふつうの `.json`・`.txt`・画像・`CREATE TABLE` だけの `.sql`・公開してよいキー | 数えない |

`dist/`・`build/`・`out/` などは従来どおり調べない（ビルドの出力のため）。

## 4. Stripe・AWS（`src/detect/secret-defs.ts` の定義データ）

詳細は [`secret-definitions.md`](secret-definitions.md) の表。要点：

- Stripe：`sk_live_`・`rk_live_` は秘密（名前がなくても値の形で探す）。`pk_` は公開可能。`sk_test_`・`rk_test_` はテスト用として数えない。
- AWS：`AWS_SECRET_ACCESS_KEY`（credentials ファイルの `aws_secret_access_key`・SDK の `secretAccessKey` を含む）に入った 40 文字のランダムな値だけ。接頭辞がないので、名前のない値は探さない。アクセスキー ID だけでは数えない。
- 環境変数ではない書き方のために、定義に `codeNames` を加えた。`opaque` の判定に、使われる文字（`charset`）と最大の長さを指定できるようにした。

## 5. Windows でのビルドの修正

Windows（WinLibs の MinGW-w64）で `npm run build:win` を通すため、次の2点を直した。Linux でのビルドの結果は変わらない。

- `native/windows-host/include-shim/EventToken.h`：大文字小文字を区別しない Windows では自分自身を読み込み続けていたため、`#include_next` にした。
- `native/windows-host/host.cpp`：MinGW-w64 の配布によって `_WIN32_WINNT` の既定値が違い、`GetDpiForWindow` が使えなかったため、Windows 10（`0x0A00`）を明示した。

ビルドに使う Node.js のバージョンが埋め込まれる（今回は v24.18.0）。

## 6. テスト

`test/exposure.test.ts`（22件）。各項目に positive / negative / dummy / safe のケースがある。鍵はテストのたびに `crypto.generateKeyPairSync` で作り、値は乱数で作る。値・鍵が、判定結果・チェック・画面の HTML・コンソールへの出力のどこにも出ないことを確かめる。
