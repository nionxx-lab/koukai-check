# Windows 版の配布（GitHub Actions → GitHub Release）

Phase 4.12（2026-10-10）から、Windows の exe は Git にコミットしない。GitHub Actions でテスト・ビルドし、GitHub Release の添付ファイルで配布する。

ワークフロー：`.github/workflows/koukai-check-windows.yml`（アプリのフォルダは `APP_DIR`。公開リポジトリでは `.`）

## 流れ

```
公開ソース（タグ）
  → test：windows-latest で npm ci・型の確認（npm run typecheck）・全テスト（npm test）
  → build：test が成功したときだけ。MinGW-w64（WinLibs・SHA256 照合）を取得 → npm run build:win
           → 生成した exe の構造テスト → SHA256 を別の方法（Get-FileHash）で照合 → build provenance → artifact
  → release：タグのときだけ。Release を「下書き」で作り、ファイルを添付する（公開はしない）
```

| きっかけ | test | build | release |
|---|---|---|---|
| PR（`koukai-check/**` かワークフローを変えたとき）・手動実行 | ○ | ○（artifact に 14 日） | — |
| タグ `koukai-check-v<package.json のバージョン>` | ○ | ○ | 下書き（本番用） |
| タグ `koukai-check-ci-test-<任意>` | ○ | ○ | 下書き・プレリリース。題名に「[CI TEST・公開しない]」 |

- 本番用のタグは、`package.json` のバージョンと一致しなければ止まる（例：0.1.0 なら `koukai-check-v0.1.0`）。
- 同じタグの Release がすでにあれば止まる（上書きしない）。
- Node.js（24.18.0）と MinGW-w64（WinLibs gcc 16.2.0 / mingw-w64 14.0.0 r1）は版を固定する。WinLibs は公式の SHA256 と照合してから使う。

## 添付するファイル

| ファイル | 内容 |
|---|---|
| `koukai-check-<版>-win-x64.exe` | 本体 |
| `SHA256SUMS.txt` | 下の4つのファイルの SHA256（`sha256sum -c` の形）。コメント行に、ソースのコミット・元にした公式 node.exe・専用ウィンドウ・WebView2Loader.dll の SHA256 |
| `BUILD-INFO.txt` | ソースのコミット・ワークフローの実行の URL・ランナー・Node.js・コンパイラの版 |
| `THIRD-PARTY-NOTICES.txt` | Node.js・WebView2 SDK のライセンス |
| `README-ja.txt` | 利用者向けの説明（はじめにお読みください）。GitHub の Release は日本語のファイル名を受け付けず「default.txt」に変えてしまうため、ASCII の名前にしている（ワークフローでも、ASCII 以外の名前があれば止める） |

SHA256 は、ビルドスクリプト（`scripts/build-windows-exe.mjs`）が Node.js の `crypto` で作り、ワークフローが PowerShell の `Get-FileHash` でもう一度計算して一致を確かめる。BUILD-INFO.txt のコミットがビルド対象（`GITHUB_SHA`）と一致することも確かめる。

## build provenance（attestation）

`actions/attest-build-provenance` で、exe と SHA256SUMS.txt に「このリポジトリ・このコミット・このワークフローで作った」ことの証明を付ける。確認は次のとおり。

```
gh attestation verify koukai-check-0.1.0-win-x64.exe -R nionxx-lab/koukai-check
```

**制約**：GitHub の Free / Pro / Team プランでは、artifact attestation は公開リポジトリでしか使えない（非公開リポジトリは GitHub Enterprise Cloud が必要）。このリポジトリは現在非公開のため、このステップは自動で飛ばし、代わりに BUILD-INFO.txt（コミット・ワークフローの実行の URL）と Actions の実行記録で追跡する。リポジトリ（または配布用のリポジトリ）を公開すると、ワークフローを変えずに provenance が付く。

**注意**：非公開リポジトリの Release は、一般の利用者がダウンロードできない。一般に配布する前に、リポジトリを公開するか、配布用の公開リポジトリを用意するかを Owner が決める必要がある。

## Owner が Release を公開する前に確認すること

1. **Actions の実行**：test・build・release の3つがすべて成功している。test のログに `ℹ fail 0` がある
2. **コミット**：Release の本文・BUILD-INFO.txt の「ソースのコミット」が、公開したいコミットと一致している
3. **SHA256**：ダウンロードした exe で `Get-FileHash .\koukai-check-<版>-win-x64.exe -Algorithm SHA256` を実行し、SHA256SUMS.txt・Release の本文の値と一致する
4. **provenance**：公開リポジトリなら `gh attestation verify …` が成功する（非公開のあいだは 2. で代える）
5. **実機での確認**（Windows 10 / 11）
   - ダブルクリックで起動し、黒い画面（コンソール）が出ない
   - 「公開前チェック」の専用ウィンドウが開く（ブラウザは開かない）
   - 「チェックするアプリのフォルダを選ぶ」でフォルダを選べ、結果が表示される
   - 秘密情報の値（キー・トークン・秘密鍵の中身）が画面に出ていない
   - 「終了する」・ウィンドウの × で終わり、プロセスが残らない
6. **添付ファイル**：exe・SHA256SUMS.txt・BUILD-INFO.txt・THIRD-PARTY-NOTICES.txt・README-ja.txt がそろっている
7. **区別**：題名に「[CI TEST・公開しない]」が付いた Release ではない（テスト用の下書きは、確認後に Release とタグを削除する）

確認できたら、GitHub の Releases 画面で下書きを開き、「Publish release」を押す。

## 移行について

- `release/windows/*.exe`・`SHA256SUMS.txt`・`THIRD-PARTY-NOTICES.txt`・`BUILD-INFO.txt` を `.gitignore` に入れ、通常のコミットで Git の管理対象から外した（`git rm --cached`。手元のファイルは消していない）。
- **過去の履歴は書き換えていない**。以前のコミットに入っている exe（3つの版、約 87〜93MB）は履歴に残る。リポジトリを小さくするには履歴の書き換えが必要で、Owner の判断事項とする。

## CI で見つかって直したこと（2026-10-10〜11）

| 見つかったこと | 原因 | 直し方 |
|---|---|---|
| テストが30分止まり、ジョブの制限時間でキャンセルされた（同じ時刻のタグの実行では2分で成功） | Windows で Ctrl+C を送る仲立ち（PowerShell）の準備（C# のコンパイル）に時間がかかり、混んだランナーでは、アプリの起動を待つ 10 秒の中に食い込んだ。さらに、失敗したあと子プロセスを終了していなかったため、テストのプロセスが終われなかった | 仲立ちが子プロセスを起動し終えたら知らせ（`ready`）、テストはそれを待ってから起動時間を測る（アプリに求める 10 秒は変えていない）。失敗しても `finally` で子プロセスまでまとめて終了する（Windows は `taskkill /T`）。Ctrl+C が要らない実行は仲立ちを使わない。仲立ち自体のテスト（`test/interruptible.test.ts`）を追加 |
| `はじめにお読みください.txt` が Release で `default.txt` になった | GitHub の Release は ASCII 以外のファイル名を受け付けない | `README-ja.txt` に改名し、ASCII 以外の名前があれば下書きを作る前に止める |
| フォルダ選択のテストが失敗した | ランナーの一時フォルダが `C:\Users\RUNNER~1\…`。アプリは `~` を `%7E` にする（正しい）が、テストは `encodeURIComponent`（`~` のまま）で期待値を作っていた | 行き先を URL として解析し、path が一致するかで確かめる |
| actions の Node.js 20 廃止の警告 | checkout・setup-node・upload-artifact が v4 | Node.js 24 で動く最新版に上げた |
