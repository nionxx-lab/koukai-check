# 変更の履歴

## 0.1.0（最初の公開版・Windows 版のみ）

このリポジトリは、作者の非公開の開発リポジトリから、完成した状態を最初のコミットとして移したものです。

- **移行元**：非公開の開発リポジトリのコミット `d1c65d6`（MVP の診断機能を凍結し、公開前の監査を終えた状態）に、公開前の整理（作者固有の情報の置き換え・SECURITY.md などの追加）を加えた状態
- 開発中の履歴（作り直す前の実装・開発途中の Windows の exe など）は移していません。判定の根拠・意図的に検出しないもの・開発中に見つけて直した問題は、`docs/` の設計の文書に残しています

### できること

- アプリのフォルダを選ぶだけで、使っている技術（Supabase・Firebase・Next.js・Expo・外部 API など）を判定し、必要なチェックだけを表示
- 秘密のキー・トークンの直書き（Stripe・AWS・Supabase・OpenAI・Anthropic・ElevenLabs・GitHub・Claude Code・データベースの接続情報）。テスト用・ダミー・公開してよいキーは数えない（`docs/secret-definitions.md`）
- Git の履歴に残った秘密情報（push 済みかどうか。同じ値は1件にまとめる。Git がなければ飛ばす）（`docs/phase4.13-git-history.md`）
- 秘密鍵・サービスアカウント鍵のファイル、公開フォルダ（`public/`・`static/`）への危険なファイルの混入、Firebase のセキュリティルール（`docs/phase4.10-publish-accidents.md`）
- `.env` が Git に入ってしまわないか
- Supabase 公式の Security Advisor の結果を、初心者向けに表示（利用者が開始した場合だけ通信）
- Windows の専用ウィンドウ（WebView2）。黒い画面・ブラウザは開かない
- 値を画面・ログ・HTML に出さない。作者のサーバーへ送らない。ファイル・Git の履歴を書き換えない

### ライセンス

- koukai-check 本体は PolyForm Shield License 1.0.0（source-available。個人・商用を問わず利用できる。koukai-check または実用的な代替品と競合する製品の提供には使えない）
- 名前とロゴは許諾の対象外（TRADEMARKS.md）
- exe に含まれる第三者のソフトウェア（Node.js・WebView2 SDK・MinGW-w64 のランタイム・GCC のランタイムライブラリ）のライセンスの全文を、THIRD-PARTY-NOTICES.txt に含める
- テスト・サンプルの Supabase の診断結果の例は、API の構造・項目名・lint の名前だけを残し、説明の英文は独自の文にした

### 配布

- GitHub Actions（Windows）でテスト・ビルドし、`SHA256SUMS.txt`・`BUILD-INFO.txt`・build provenance を付けて GitHub Releases で配布（`docs/release-windows.md`）
- まだ電子署名はありません（Windows の SmartScreen の警告が表示されます）
