# Phase 4.11：Windows での開発・テスト・ビルドの安定化

実施日: 2026-10-10
範囲: 新しい機能は追加していない。Windows を正式なサポート環境として、全テストが安定して通り、exe のビルドが警告なしで通る状態にした。

## 1. Windows で失敗していた12件

| 原因 | 失敗していたテスト | 直し方 |
|---|---|---|
| `node --import <絶対パス>`：Windows の `C:\…` は URL のスキーム `c:` と読まれる（`ERR_UNSUPPORTED_ESM_URL_SCHEME`） | E2E のトークン漏洩監査5件・通信先監査・保存HTML・一般ユーザー向けの画面（8件） | `pathToFileURL(…).href` を渡す |
| `child.kill('SIGINT')`：Windows にはシグナルがなく、子プロセスを強制終了する（終了処理が走らず終了コードは null） | 「起動してローカルでレポートを配信し、Ctrl+C で終了する」、E2E の Ctrl+C を使う確認 | `test/helpers/interruptible.ts`：Linux・macOS は SIGINT。Windows は子プロセスを専用の（見えない）コンソールで起動し、そこへ本物の Ctrl+C イベント（`GenerateConsoleCtrlEvent`）を送る。利用者が Ctrl+C を押したときと同じ経路で、Node.js では SIGINT として届く。終了コード 0・「終了しました」の表示まで確かめる（期待値は変えていない） |
| `execFileSync('npm')`：Windows の npm は `npm.cmd` で、Node.js はセキュリティ上の理由で `.cmd` をシェルなしで起動しない（`ENOENT`） | npm 配布物 | npm 本体（`npm-cli.js`）を `node` で起動する（`npm_execpath`・公式インストーラーの場所の順に探す） |
| `--dev-window-host` に `.sh` を渡していた（Windows は実行できない） | 代役の専用ウィンドウでの確認2件 | 開発用の `--dev-window-host` に `.js` を渡したら、いまの Node.js で起動するようにした（exe 版では使わない）。テストは全OSで `.js` を渡す |
| フォルダ名に `<` `>` を使っていた（Windows ではフォルダ名にできない） | フォルダ名の HTML エスケープ | 実際のフォルダは全OSで使える `' & \` = ( )` で属性を壊す名前にし、サーバー経由でエスケープを確かめる。タグ（`<img …>`）は画面を作る処理に直接渡して確かめる（どちらも全OSで実行） |

あわせて、テストで環境変数を絞って子プロセスを起動するときは、Windows に必ずある `SystemRoot` などを足すようにした（`windowsBaseEnv()`）。

### skip について

- 「Windows ではシンボリックリンクの作成に権限が必要」で丸ごと skip していたテストを分けた。フォルダのリンクは、Windows では権限なしで作れるジャンクションで**全OSで実行**する。ファイルのシンボリックリンクは、作れる環境（Linux・macOS・Windows の開発者モード）でだけ実行する（作れない環境では利用者のフォルダにも存在しえない）。
- `app.test` の「シンボリックリンクはたどらない」は、作れないと何も確かめずに成功していた。ジャンクションで実際に確かめるようにした。
- 「SEA 版（Linux・動作確認用）」は Linux のビルドでだけ作られる実行ファイルを使うため、Windows では skip のまま。Windows の exe は、構造のテスト（下の 3.）と実機での起動確認で確かめる。

## 2. flaky test「応答が大きすぎる場合」

**原因**：CPU・IO の負荷に依存する競合。テストのクライアントのタイムアウトは 300ms（本文の受信中も効く）。一方、2つ目のケースは上限（20MB）を超えるまで実際に 21MB を流していた。

| 状況 | 21MB の受信にかかった時間 |
|---|---|
| 単独・負荷なし（このPC） | 26〜52ms |
| 単独・CPU 8スレッドに負荷 | 41〜78ms |
| 全テストの並行実行中（テストに計測を入れて3回） | 89・245・267ms |

全テスト実行中は 300ms すれすれになり、超えると受信中にタイムアウトして `network` になっていた（失敗時の実際の値も `network`）。ポートは毎回 OS が割り当て（0番）、テスト間で共有する状態・子プロセスはなく、送信側は `drain` を待っており backpressure も正しかった。

**直し方**：タイムアウトは延ばしていない。クライアントに応答の上限を指定できるようにし（`maxResponseBytes`。既定は従来どおり 20MB）、受信しながら止める確認は小さな上限（64KB）で行う。20MB という実際の値は `Content-Length` の申告で確かめ、上限ちょうどの応答を受け付けることも確かめる。

## 3. exe のビルドの警告

### `.rsrc merge failure: multiple non-default manifests`（リンク時）

**無害ではなかった**。専用ウィンドウ（koukai-check-window.exe）に、同じ ID・言語のマニフェストが2つ入っていた（`app.manifest`：DPI 対応・Common Controls 6 と、MinGW-w64 の既定のマニフェスト）。Windows がどちらを使うかは決まっておらず、既定の方が使われると高 DPI でぼやけるおそれがあった。

原因：gcc は `default-manifest.o` を必ずリンクする（`gcc -dumpspecs` の `%:if-exists(default-manifest.o%s)`）。Ubuntu の配布ではリンカーが既定のマニフェスト（言語 0）を見分けて捨てるが、WinLibs の既定のマニフェストは言語が 0x409 で見分けられなかった。

直し方：`app.rc` からマニフェストを外し、リンクのあとでビルドスクリプトが RT_MANIFEST をすべて取り除いて `app.manifest` を1つだけ入れる。入っているのが `app.manifest` の1つだけでなければビルドを止める。どの配布の MinGW-w64 でも同じ結果になる。

### `Relocation corrupted: BlockSize is out of bound the binary's virtual size`（postject の埋め込み時）

**exe の再配置情報は壊れていなかった**（526 ブロック・94,144 項目をすべて読み、どれも exe の範囲内）。原因は、アイコン・バージョン情報を差し替える resedit が `.rsrc` を書き直したとき、メモリ上の大きさだけを縮め、ファイル上の大きさ（SizeOfRawData）を元のまま残していたこと。`.rsrc` のファイル上の範囲が次の `.reloc` と重なって見え、postject（LIEF）が再配置情報を誤った場所から読んで警告していた。Windows のローダーはメモリ上の大きさで読むため動作はしていた。

直し方：resedit の `outputResource(exe, false, true)`（allowShrink）で、ファイル上の大きさも合わせて縮める。警告は出なくなった。さらに、生成した exe を `checkPeLayout` で検査し（セクションのファイル上の範囲が重ならない・再配置情報を最後まで読める）、問題があればビルドを止める。テストでも、わざと壊した exe を見つけることを確かめる。

### Windows でのビルド

WinLibs（`winget install BrechtSanders.WinLibs.POSIX.UCRT`）では `windres` に接頭辞が付かないため、Windows では接頭辞なしの名前も探すようにした。WinLibs の `mingw64\bin` を PATH に入れて `npm run build:win` を実行する。

## 4. 確認結果

- `npm test`（ビルド・型の確認を含む）を同じPCで5回連続：すべて成功（各回 失敗 0）
- `npm run build:win`：警告なし。生成した exe を実機で起動し、フォルダのチェック結果を表示、ウィンドウを閉じると exe・専用ウィンドウのプロセスがすべて終了することを確認

## 5. 次フェーズ案：exe を Git にコミットしない配布方式

現状：`release/windows/` に 89MB の exe をコミットしている。再生成のたびに履歴が 89MB ずつ増え（履歴からは消えない）、GitHub の1ファイル 100MB の上限にも近い。

| 方式 | 利用者が入手できるか | 保存期間 | 追跡できるか | 判断 |
|---|---|---|---|---|
| 今のまま Git にコミット | できる | 永久（履歴が増え続ける） | コミットは分かるが、どの手順で作ったかは分からない | やめる |
| Git LFS | できる | 永久 | 同上 | 無料枠（容量・転送量）が小さく、根本的な解決にならない |
| GitHub Actions の artifacts | ログインが必要。一般の利用者向けではない | 期限つき（既定 90 日） | ワークフローの実行と結び付く | PR の確認用（ビルドが通るか・試しに動かす）に使う |
| **GitHub Releases** | **できる（1ファイル 2GiB まで）** | **永久** | **タグ・コミットと結び付く。build provenance（証明）を付けられる** | **公開用に採用** |

おすすめの流れ（公開ソース → CI ビルド → SHA256 → Release）：

1. Owner がバージョンのタグ（例 `koukai-check-v0.1.0`）を付けて push する
2. GitHub Actions（`windows-latest`）で、`npm ci` → `npm test` → `npm run build:win`。Node.js と MinGW-w64 のバージョンは固定する
3. `SHA256SUMS.txt` を作り、`actions/attest-build-provenance` で exe の build provenance（どのコミット・どのワークフローで作ったかの証明）を付ける。利用者・Owner は `gh attestation verify` で確かめられる
4. exe・`SHA256SUMS.txt`・`THIRD-PARTY-NOTICES.txt`・はじめにお読みくださいを、Release の**下書き**に添付する
5. Owner が実機で確認してから Release を公開する（GO 判断は Owner）
6. PR では同じワークフローで exe を artifacts（保存 7〜14 日）に上げ、確認用に使う

移行の手順（次フェーズ。今回は行っていない）：ワークフローを追加 → `release/windows/*.exe` を `.gitignore` に入れ、通常のコミットで exe を取り除く（履歴の書き換えはしない。過去のコミットの exe は残る）→ README のダウンロード先を Releases にする。

注意点：
- 今のビルドは**同じソースからでも exe が完全に一致しない**（今回、2回のビルドで SHA256 が違った。リンカーのタイムスタンプなど）。そのため「同じものを作り直して照合する」のではなく、CI のビルドに付けた provenance で追跡する。完全に再現できるビルド（タイムスタンプの固定など）は別の課題とする。
- Windows の作業コピーでは改行が CRLF になり（`core.autocrlf`）、exe に入る `app.manifest` の中身が OS で変わる。CI では `.gitattributes` で改行を固定する。
- SmartScreen の警告を減らすコード署名（Authenticode）は、費用がかかるため別に判断する。
