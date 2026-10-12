# 不具合修正：アプリのルートを選んだのに「使っている技術を判定できませんでした」と出る

修正日: 2026-10-08
報告: Windows 実機で `C:\Users\あなた\デスクトップ\projects\sample-app`（直下に `package.json` があるアプリのルート）を選ぶと、
「使っている技術を判定できませんでした」「package.json が入っているフォルダを選び直してください」「フォルダが大きいため、一部だけを調べました」と表示された。

## 原因

`src/detect/scan.ts` の走査では、ルート直下は最初に調べていた。それでも取りこぼしたのは、次の3つが重なったため。

1. **BOM 付きの package.json を読めなかった（最も可能性が高い）。**
   Windows の PowerShell 5.1（`Out-File` / `Set-Content -Encoding utf8`）や一部のエディタは、UTF-8 のファイルの先頭に BOM（`EF BB BF`）を付ける。
   旧コードは `readFileSync(path, 'utf8')` の結果をそのまま `JSON.parse` していたため、BOM があると例外になり、
   その例外を「読み取れなかった数」に1を足すだけで黙って捨てていた。
   その結果、package.json があっても依存パッケージを1つも読めず、技術を判定できなかった。
   （同じ理由で、BOM 付きの `.env` では最初の変数名に BOM が混ざっていた。）
2. **「判定できなかった」の説明が、package.json がない場合と同じだった。**
   package.json を見つけたのに読めなかった場合や、読めたが対応している技術がなかった場合でも、「package.json が入っているフォルダを選び直してください」と表示していた。
3. **深さの上限に当たっただけで「フォルダが大きいため、一部だけを調べました」と表示していた。**
   深さ4より深いフォルダ（例：`src/app/(dashboard)/settings/profile/…`）はふつうのアプリでもよくあるため、小さなフォルダでもこの表示が出ていた。

旧コードでも、BOM 付きの package.json と深いフォルダが1つあるだけ（全体で6件）のフォルダで、3つの表示がすべて再現した。

あわせて、直下の項目が件数の上限（20,000件）を超えるようなフォルダでは、名前順で後ろにある `package.json` などを調べる前に打ち切る可能性もあった（今回の報告の直接の原因ではない可能性が高いが、同時に直した）。

## 修正

| 修正 | 内容 |
|---|---|
| 直下の優先確認 | 選んだフォルダの直下の `package.json`・`.env` 系・主要な設定ファイル（`app.json`・`app.config.*`・`eas.json`・`next.config.*`・`firebase.json`・`.firebaserc`・`google-services.json`・`GoogleService-Info.plist`・`firestore.rules`・`storage.rules`・`supabase/config.toml`）を、**件数・深さの上限に関係なく最初に確認する**。そのあとの全体の走査では二重に数えない |
| BOM | ファイルの先頭の BOM を取り除いてから読む（package.json・.env・app.json・.gitignore） |
| package.json の状態 | 直下の package.json が「あり（読めた）」「あるが読めない」「ない」を区別し、判定できなかったときの説明を変える。選び直しを案内するのは「ない」ときだけ |
| 上限の表示 | 件数の上限に達したときだけ表示し、「直下の package.json・.env・設定ファイルは確認済み」と書く。深さの上限は表示しない（`stats.depthLimited` として記録だけする） |

変えていないこと：深さ（4）・件数（20,000）・ファイルの大きさ（1MB）の上限、`node_modules` などの除外、シンボリックリンクをたどらないこと（直下の優先確認でも同じ。`supabase` フォルダがリンクの場合も読まない）、日本語のパス。

## テスト

`test/scan.test.ts`（新規、再現ケース `sample-app` を日本語の親フォルダの下に作る）：
- BOM 付きの package.json・.env.local、20,100件のファイル、深いフォルダ → Supabase・Next.js・.env を判定し、プロジェクトIDも見つかる。「判定できませんでした」「選び直してください」は出ない
- 直下の項目だけで件数の上限を超えていても、package.json・.env・firebase.json・supabase/config.toml を確認する
- 深さの上限に当たっただけでは「一部だけを調べました」を出さない
- package.json はあるが対応する技術がない／壊れている／ない、の説明の違い
- node_modules の中は見ない、直下の package.json・.env・supabase フォルダがシンボリックリンクならたどらない

旧コードでは再現ケースのテストが失敗し、修正後は全 288 件が通過する。
Windows 版 exe（wine 上の Windows 用 Node.js）でも、同じ構成のフォルダで Next.js・Supabase を判定できることを確認した。

## Windows 実機で確かめてほしいこと

1. 同じフォルダ（`sample-app`）を選び直し、使っている技術が表示されること。
2. （任意・原因の確認）PowerShell で次を実行し、先頭が `239 187 191` なら BOM 付きだった（今回の原因と一致）。
   ```powershell
   [System.IO.File]::ReadAllBytes("C:\Users\あなた\デスクトップ\projects\sample-app\package.json")[0..2]
   ```
   `123`（`{`）で始まる場合は BOM ではなく、別の原因（対応している技術が依存に含まれていない、など）。そのときは画面の新しい説明を教えてください。
