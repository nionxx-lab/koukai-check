# Phase 4.6：Windows 向けのダブルクリック起動（Node.js SEA）

実施日: 2026-10-08
範囲: 現在の Folder-first 版を、Node.js・npm・npx・ターミナルの操作なしに Windows で起動できるようにすること。新しい診断機能は追加していない。

> **Phase 4.7 で起動方式を変更しました。** 黒いコンソール画面と既定のブラウザは使わず、「公開前チェック」の専用ウィンドウ（WebView2）に表示します。
> 最新の動き・確認手順は [`windows-app-window.md`](windows-app-window.md) を参照してください。
> このページのうち、SEA のビルドの仕組み（1ファイルへの結合・node.exe の照合・署名の除去・埋め込み）は今も同じです。
> 「黒い画面」「既定のブラウザ」「PowerShell のフォルダ選択」「W-1〜W-17」の記述は Phase 4.6 時点のもので、exe 版にはもう当てはまりません。

## 方式：Node.js Single Executable Applications（SEA）を採用

| 検討した方式 | 判断 |
|---|---|
| **Node.js SEA** | **採用**。Node.js 公式の仕組みで、追加の実行時依存がない。現在の構成（依存パッケージ0個・Node 標準APIのみ・ブラウザで表示する画面）とよく合う |
| pkg / nexe | 開発が止まっている、または Node 22 への対応が不確実なため見送った |
| Electron / Tauri | 依存パッケージが大きく増え、更新や監査の負担が大きいため見送った（ブラウザで表示する画面で足りる） |

SEA の制約と対応：
| 制約 | 対応 |
|---|---|
| 起点は CommonJS の1ファイル | `tsconfig.sea.json` で CommonJS として出力し、`scripts/build-windows-exe.mjs` の自前の結合処理で1ファイルにした。依存パッケージが0個なので、esbuild などは使っていない。node: 以外の require が紛れ込んだらビルドを失敗させる |
| Linux 上で Windows 用を作る | コードキャッシュとスナップショットを使わなければ、blob は OS をまたいで使える。そのうえで、同じバージョン（v22.22.0）の公式 `node.exe` に埋め込んでいる |
| 「実験的な機能」の警告 | `disableExperimentalSEAWarning: true` で表示しない |
| 署名 | 公式 `node.exe` の Authenticode 署名は、埋め込み前に外す（書き換えると壊れた署名になるため） |

## ビルド手順（作者側）

```bash
cd koukai-check
npm install          # 開発用：typescript, @types/node, postject（配布物には含まれない）
npm run build:win
```

1. TypeScript を CommonJS で出力する（`build/sea/cjs`）。
2. 1ファイルに結合する（34モジュール → `build/sea/koukai-check.cjs`）。
3. SEA の blob を作る。パスは相対で指定し、開発環境のパスを残さない。
4. `https://nodejs.org/dist/v22.22.0/win-x64/node.exe` を取得し、**公式の `SHASUMS256.txt` と照合する**。一致しなければビルドを止める。
5. Authenticode 署名を外す（`signtool remove /s` と同じ処理）。
6. postject で `NODE_SEA_BLOB` を埋め込み、SEA を有効にする印（fuse）を立てる。
7. 動作確認用に、同じ blob を埋め込んだ Linux 版も作る（`build/sea/koukai-check-linux-x64`。配布しない）。

生成物に開発環境のパスが含まれていたら、ビルドを失敗させる。

## 生成物

> Phase 4.12 から、exe・`SHA256SUMS.txt`・`THIRD-PARTY-NOTICES.txt`・`BUILD-INFO.txt` は Git にコミットしない（`.gitignore`）。GitHub Actions でビルドし、GitHub Release の添付ファイルで配布する（[`release-windows.md`](release-windows.md)）。

| ファイル | 内容 |
|---|---|
| `release/windows/koukai-check-0.1.0-win-x64.exe` | Windows（x64）用の実行ファイル（生成物・Git に入れない） |
| `release/windows/SHA256SUMS.txt` | 添付するファイルすべての SHA256、ソースのコミット、元にした公式 node.exe などの SHA256（生成物） |
| `release/windows/BUILD-INFO.txt` | ソースのコミット・ビルドした環境（GitHub Actions の実行・Node.js・コンパイラの版）（生成物） |
| `release/windows/THIRD-PARTY-NOTICES.txt` | 同梱しているソフトウェアのライセンス（生成物） |
| `release/windows/README-ja.txt` | 利用者向けの短い説明（Git で管理するソース） |

exe の構造は検査済み（PE32+ / x64、コンソールアプリ、署名なし、`.rsrc` に NODE_SEA_BLOB、fuse 有効）。

## exe 版で変えたこと（コード）

- `src/cli/standalone.ts`（新規）：`node:sea` の `isSea()` で exe として起動されたかを判定する。
- exe 版では、起動時に「この黒い画面は、使い終わるまで閉じないでください（閉じると公開前チェックも終了します）。」と表示する。
- 予期しないエラーで終了するときは、黒い画面がすぐ閉じてメッセージを読めない、ということがないよう、Enter キーを待つ。
- それ以外の動き（引数なしで画面を開く・フォルダの解析・Supabase 診断・開発用CLI）は、`npx` 版と同じコード。

## フォルダ選択の画面が exe 版でも動く仕組み

- フォルダ選択の画面は、Node.js ではなく **Windows に標準で入っている PowerShell（`powershell.exe`）** で開く。exe からは子プロセスとして呼ぶだけ。
  - 中身は `System.Windows.Forms.FolderBrowserDialog`。
  - 日本語の文字化けを防ぐため、`-EncodedCommand`（UTF-16LE の Base64）で渡す。
  - 結果は UTF-8 で受け取る。
  - ブラウザの裏に隠れないよう、最前面（TopMost）の親ウィンドウを付けて表示する。
  - `-ExecutionPolicy Bypass` を付けるので、スクリプトの実行ポリシーで止められない。
- 選ばれたパスは、ローカルサーバーがそのまま受け取って解析する。ブラウザにファイルの中身を読み込ませる方式（webkitdirectory）は使っていない。
- PowerShell を起動できない、または組織の制限で失敗した場合は、画面上の「フォルダの場所を貼り付けてください」の欄に切り替わる（Phase 4.5 から変更なし）。

## 利用者がダウンロード後に行う操作

1. `koukai-check-0.1.0-win-x64.exe` をダウンロードする。
2. ダブルクリックする。
3. 「Windows によって PC が保護されました」と表示されたら、「詳細情報」→「実行」を押す（初回のみ。§警告を参照）。
4. 黒い画面が開き、続けてブラウザで「公開前チェック」の画面が開く。
5. 「チェックするアプリのフォルダを選ぶ」→ フォルダを選ぶ → 結果を見る。
6. 「終了する」を押す（黒い画面も閉じる）。

## Windows Defender / SmartScreen で想定される警告

| 警告 | 理由 | 対応 |
|---|---|---|
| **SmartScreen「Windows によって PC が保護されました」**（発行元: 不明） | コード署名がなく、ダウンロード数の実績もないため | 「詳細情報」→「実行」で起動できる。根本的な対応は、コード署名証明書（OV / EV）で署名すること（Phase 5 以降で検討） |
| ブラウザの「このファイルは一般的にダウンロードされていません」 | 同上（Edge / Chrome の評価） | 「保持する」を選ぶ。署名と配布実績で改善される |
| **Microsoft Defender の誤検知**（まれ） | 単一の実行ファイルにまとめたツール（SEA / pkg 系）は、ヒューリスティックで誤検知されることがある | 起きた場合は Microsoft に誤検知として報告する。SHA256 を公開して、利用者が照合できるようにしている |
| 初回起動が遅い | Defender が 82MB のファイルを検査するため | 2回目以降は速くなる |
| ファイアウォールの警告 | **出ない想定**（127.0.0.1 だけで待ち受けるため） | もし出た場合は記録する |

## Windows 実機での確認手順（チェックリスト）

確認日：＿＿＿＿　Windows のバージョン：＿＿＿＿　既定のブラウザ：＿＿＿＿

**Node.js がインストールされていない PC**（またはアンインストールした状態）で行う。

| # | 手順 | 期待する結果 | 結果 |
|---|---|---|---|
| W-1 | PowerShell で `Get-FileHash .\koukai-check-0.1.0-win-x64.exe -Algorithm SHA256` を実行する | `SHA256SUMS.txt` の値と一致する | |
| W-2 | exe をダブルクリックする | SmartScreen の警告が出る／出ない（どちらか記録する）。「詳細情報 → 実行」で起動する | |
| W-3 | 起動後 | 黒い画面に「この黒い画面は、使い終わるまで閉じないでください」と表示され、既定のブラウザで画面が開く | |
| W-4 | ファイアウォールの警告 | 出ない | |
| W-5 | 「チェックするアプリのフォルダを選ぶ」を押す | Windows の「フォルダーの参照」画面が**ブラウザの手前に**開く | |
| W-6 | 日本語を含むパスのフォルダ（例：`C:\Users\山田\Desktop\テストアプリ`）を選ぶ | 結果の画面にフォルダ名が正しく表示される | |
| W-7 | 選択画面で「キャンセル」を押す | 「フォルダが選ばれませんでした」と表示される | |
| W-8 | Expo + Supabase のアプリのフォルダを選ぶ | Supabase・Expo などが判定され、「Supabase のチェックを始める」が出る | |
| W-9 | Supabase を使っていないアプリのフォルダを選ぶ | Supabase 関連の表示が出ない | |
| W-10 | Supabase のチェック（トークンを貼り付け） | 日本語のレポートが表示される（`docs/manual-e2e-check.md` 参照） | |
| W-11 | 「AIに修正を頼む指示をコピー」 | 貼り付けると指示文が入る | |
| W-12 | 「終了する」 | ブラウザに「終了しました」と表示され、**黒い画面も自動で閉じる**。タスクマネージャーに `koukai-check` が残っていない | |
| W-13 | もう一度起動し、黒い画面を右上の × で閉じる | ツールが終了する（タスクマネージャーに残らない） | |
| W-14 | もう一度起動し、黒い画面で Ctrl+C | 「終了しました。」と表示されて閉じる | |
| W-15 | 30分以上そのまま置く | 自動で終了する（任意） | |
| W-16 | 社内PCなどで PowerShell が制限されている環境 | 「フォルダの場所を貼り付けてください」の欄に切り替わり、パスを貼り付けて使える | |
| W-17 | 通信の確認（任意）：「リソースモニター」→「ネットワーク」で koukai-check を確認する | 127.0.0.1 と（Supabase のチェック時のみ）api.supabase.com だけ | |

## まだ確認していないこと

- **Windows の実機で exe を実際に起動すること**（この環境は Linux で、wine もない）。
  - 確認済みなのは次の範囲：
    - 同じ blob を埋め込んだ Linux の SEA 版で、全体の流れが動くこと（自動テストとブラウザで確認）。
    - Windows 版の exe の構造の検査。
  - Windows 固有の動作は、すべて上の W-1〜W-17 で確認する必要がある：
    - PowerShell のダイアログ
    - `cmd /c start` でのブラウザ起動
    - 黒い画面を閉じたときの終了
    - SmartScreen
- SmartScreen / Defender が実際にどう反応するか。
- ARM 版 Windows（x64 のエミュレーションで動く想定）。
- exe のアイコンとバージョン情報（Node.js のものが表示される。変えるには rcedit などが必要で、Phase 5 以降で検討する）。
- コード署名（Phase 5 以降）。

## 配布について

- Phase 4.12 で、GitHub Releases での配布に移した（[`release-windows.md`](release-windows.md)）。exe は Git の管理対象から外した。過去のコミットに入っている exe は、履歴を書き換えないため残っている。
