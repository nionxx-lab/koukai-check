# 秘密情報の定義リスト（Phase 4.9）

作成日: 2026-10-09
範囲: 秘密情報の検出を、`CLAUDE_CODE_OAUTH_TOKEN` 専用から、**サービスごとの定義データを共通の仕組みが読む形**に広げた。
秘密情報の検出以外の機能（Supabase・Firebase の新しい診断など）は追加していない。

## 1. 調査結果：秘密・公開可能・条件付き

公式資料で確認できたものだけを「秘密」とした。名前に KEY・TOKEN・SECRET を含むだけでは秘密としない。

| 対象 | 分類 | 根拠（公式資料） | 値の形式の判定 |
|---|---|---|---|
| `CLAUDE_CODE_OAUTH_TOKEN` | **秘密** | Claude Code の `claude setup-token` で作る認証トークン（前フェーズで確認） | `sk-ant-oat…` ＋ ランダムな本体40文字以上 |
| `ANTHROPIC_API_KEY` | **秘密** | Claude 公式「Get your Claude API key」（https://platform.claude.com/docs/en/get-api-key）：キーは `sk-ant-` で始まり、作成時に一度だけ表示。シークレットマネージャーなどに保管。例 `sk-ant-api03-...` | `sk-ant-api…`（または `sk-ant-admin…`）＋ ランダムな本体40文字以上 |
| `OPENAI_API_KEY` | **秘密** | OpenAI 公式 SDK（openai-node）：ブラウザでの利用は既定で禁止（"it risks exposing your secret API credentials to attackers"）。案内先 https://help.openai.com/en/articles/5112595-best-practices-for-api-key-safety | `sk-` で始まる ＋ ランダムな本体32文字以上。**接頭辞の細かな種類（`sk-proj-` など）は公式資料で確認できなかったため、名前（OPENAI_API_KEY）と組み合わせたときだけ判定**し、値の形だけでは探さない |
| `ELEVENLABS_API_KEY` | **秘密** | ElevenLabs 公式「API Authentication」（https://elevenlabs.io/docs/api-reference/authentication）："The API key is a secret. Do not share it with others or expose it in any client-side code (browsers, apps)"。ブラウザでは一時トークン（single-use token）を使う | **形式は公式資料に記載がない**ため、名前と組み合わせ、32文字以上でランダムな値のときだけ本物らしいとする |
| Supabase `sb_secret_...`（`SUPABASE_SECRET_KEY`・新方式の `SUPABASE_SECRET_KEYS`） | **秘密** | Supabase 公式「Understanding API keys」（https://supabase.com/docs/guides/getting-started/api-keys）："Only use in backend components"、RLS を迂回する。「ブラウザ・配布物・ソース管理に置かない」 | `sb_secret_` ＋ ランダムな本体（名前がなくても値の形で探す）。`SUPABASE_SECRET_KEYS` が JSON の場合は、中に secret キーが含まれるかだけを判定する（値は表示・保存・ログ出力しない） |
| Supabase `service_role`（`SUPABASE_SERVICE_ROLE_KEY`） | **秘密** | 同上："Legacy version of secret keys" | JWT の `role` が `service_role`（名前がなくても値の形で探す）。ローカル開発用の鍵の扱いは下の ※ |
| Supabase `sb_publishable_...`（`SUPABASE_PUBLISHABLE_KEY`・新方式の `SUPABASE_PUBLISHABLE_KEYS`） | **公開可能** | 同上："Safe to expose online: web page, mobile or desktop app, GitHub actions, CLIs, source code" | 漏れとして数えない（秘密キーの欄に入っていても「公開してよいキー」と表示） |
| Supabase `anon`（`SUPABASE_ANON_KEY`） | **公開可能** | 同上："Legacy version of publishable keys" | JWT の `role` が `anon` は漏れとして数えない。公開キーの変数名（`NEXT_PUBLIC_` 付きを含む）に secret キーが入っていた場合だけ 🔴 |
| GitHub `ghp_` / `github_pat_` / `gho_` / `ghu_` / `ghs_` / `ghr_` | **秘密** | GitHub Docs「About authentication to GitHub」の token formats（personal access token (classic)・fine-grained PAT・OAuth・GitHub App の user / installation / refresh token）。`ghs_` は 2026年4月から長い新形式（`ghs_APPID_JWT`）も | 接頭辞で判定し、**長さは固定しない**（上限なし。本体20文字未満だけテスト用とする）。名前がなくても値の形で探す。名前は `GITHUB_TOKEN`・`GH_TOKEN` など |
| GitHub App の秘密鍵（PEM） | **秘密** | GitHub App の認証に使う秘密鍵 | `-----BEGIN … PRIVATE KEY-----` で本体200文字以上。名前（`GITHUB_APP_PRIVATE_KEY` など）と組み合わせたときだけ |
| GitHub App / OAuth App の client secret | 秘密（**今回は対象外**） | — | 値の形式が公式資料に書かれておらず、確実に見分けられないため、今回は定義していない |
| Anthropic の Admin API キー | 秘密（**今回は名前では対象外**） | 公式に別のキー（Admin API key）とあるが、接頭辞を公式資料で確認できなかった | `ANTHROPIC_API_KEY` に入っている場合だけ、`sk-ant-admin…` の形を受け付ける |
| Stripe `sk_live_` / `rk_live_`（`STRIPE_SECRET_KEY`・`STRIPE_API_KEY`・`STRIPE_RESTRICTED_KEY`） | **秘密** | Stripe 公式「API キー」（https://docs.stripe.com/keys）：シークレットキー `sk_`・制限付きキー `rk_` は「安全に公開可能：いいえ」。本番は `_live_`、サンドボックスは `_test_` | `sk_live_` / `rk_live_` ＋ ランダムな本体20文字以上（名前がなくても値の形で探す）。`sk_test_` / `rk_test_` はサンドボックスのキー（実際の決済は動かない）なので、テスト用として数えない（Phase 4.10） |
| Stripe `pk_live_` / `pk_test_`（`STRIPE_PUBLISHABLE_KEY`・`STRIPE_PUBLIC_KEY`） | **公開可能** | 同上：公開可能キー `pk_` は「安全に公開可能：はい」。「フロントエンドのコードや配信するアプリケーションに含めることができます」 | 漏れとして数えない。公開キーの変数名に `sk_live_` などが入っていた場合だけ 🔴 |
| Stripe の組織 API キー `sk_org_`・Webhook 署名シークレット `whsec_` | 秘密（**今回は対象外**） | 同上 | 組織キーは本番・サンドボックスの見分け方を公式資料で確認できず、`whsec_` は Stripe CLI のローカル用と見分けられないため、今回は定義していない |
| AWS のシークレットアクセスキー（`AWS_SECRET_ACCESS_KEY`。credentials ファイルの `aws_secret_access_key`、SDK の `secretAccessKey`） | **秘密** | AWS 公式「Manage access keys for IAM users」（https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html）：アクセスキー ID とシークレットアクセスキーの組。"Do NOT put access keys or credential information in your application files" | 接頭辞がないため、**名前と組み合わせたときだけ**、40文字・英数字と `/` `+` のランダムな値を本物らしいとする。公式の見本 `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` はテスト用（Phase 4.10） |
| AWS のアクセスキー ID（`AKIA…` / `ASIA…`） | **単独では対象外** | 同上：シークレットアクセスキーと組で使う識別子 | ID だけでは認証できないため数えない |
| AWS の一時的なセッショントークン（`AWS_SESSION_TOKEN`） | 秘密（**今回は対象外**） | — | 形式が公表されておらず、期限付きのため今回は定義していない |
| `DATABASE_URL` / `DIRECT_URL` | **条件付き** | 接続文字列（`scheme://ユーザー:パスワード@ホスト`）にパスワードが入っている場合のみ秘密 | パスワードなし・見本（`[YOUR-PASSWORD]` など）→ 数えない。接続先が localhost など → ローカル開発用。それ以外 → 本物らしい |

※ ローカル開発用の Supabase の鍵（`supabase start` が出す鍵。`iss: supabase-demo`）は、**`iss` だけでは安全扱いしない**。次の複数の根拠がそろった場合だけ「ローカル開発用」として数えない。
- `iss: supabase-demo` かつ、同じファイルにローカルの Supabase の URL（`localhost` / `127.0.0.1` の `:54321`、または `SUPABASE_…URL` が `localhost` / `127.0.0.1`）がある
- または、`iss: supabase-demo` かつ、`supabase/config.toml` があり、`.env` にローカルの Supabase の URL がある

判断できない場合は安全扱いせず、**🟠 要確認**にする（本番の鍵とも断定できないので 🔴 にはしない）。

この環境から一部の公式サイト（supabase.com・docs.github.com・elevenlabs.io・help.openai.com）に直接つながらなかったため、Supabase と GitHub は公式ドキュメントの GitHub 上の原文、ElevenLabs と OpenAI は検索結果に表示された公式ページの本文・公式 SDK のソースで確認した。

## 2. 共通の判定（すべての定義で同じ）

| 状況 | 判定 |
|---|---|
| 環境変数・シークレットの参照だけ（`process.env.〜`・`Deno.env.get(…)`・`os.environ[…]`・`${{ secrets.〜 }}`・`$〜`） | 数えない（折りたたみ「参照している場所 ○件」） |
| テスト用・ダミーの値（TEST・DUMMY などの語・短い・ランダムでない・見本の値・ローカル開発用） | 数えない（折りたたみ「テスト用・ダミーの値と判断した場所 ○件」） |
| 公開してよいキー（Supabase の publishable / anon） | 数えない（折りたたみ「公開してよいキー ○件」）。RLS の確認は従来どおり Supabase の診断で行う |
| 本物らしい値が、Git の対象外（ignore 済み）の `.env` にある | 数えない（本来の置き場所） |
| 本物らしい値が、Git で管理されている（tracked・staged・コミット済み）ファイルにある | 🔴 |
| 本物らしい値が、まだ追加されていないが .gitignore で除外されていない（untracked）ファイルにある | ソース・設定ファイル・`.env` の見本 → 🔴（ふつうコミットされる）／`.env` → 🟠（.gitignore への追加を確認） |
| 本物らしい値が、Git の対象外の `.env` 以外のファイル、または Git なしのフォルダにある | 🟠 |
| 公開用の接頭辞（`NEXT_PUBLIC_`・`EXPO_PUBLIC_`・`VITE_`・`REACT_APP_` など）の変数に秘密の値 | 🔴（.env が ignore 済みでも、アプリに埋め込まれて配布されるため） |

フォルダ名（tests・test-results など）では判断しない。値は、直書きか参照か・本物らしいかを見分けるためだけに見て、画面・ログ・HTML・診断結果・テストの出力には出さない。

## 3. 仕組み

- `src/detect/secret-defs.ts`：定義データ。各定義は、表示名・環境変数名・値の形式（`token`／`jwt-role`／`opaque`／`url-credentials`／`pem-private-key`）・値の形で探す形式（接頭辞が公式に決まっているものだけ）・公開してよい類似キー・初心者向けの説明・漏れたときの対処・根拠を持つ。
- `src/detect/secret-names.ts`：共通の仕組み。定義を読んで、`.env` 系・設定ファイル・ソースコードを探す。サービスごとの専用の処理は持たない。
- `src/checks/build.ts`：共通の重大度（`secretRisk`）と画面の項目。危険・要確認はサービスごとに「〇〇が N か所に直接書かれている可能性があります」と件数つきで出し、参照・テスト用・公開キーは1つのカードの折りたたみにまとめる（「ファイル名:行番号」だけ）。
- 分類名は「外部のAPI」ではなく **「認証情報」**（APIキー・トークン・パスワードなど、秘密にするもの）にした。
- 定義にある変数（`OPENAI_API_KEY` など）は、一般的な「外部サービスのキーはサーバー側だけで」の案内の対象から外した（定義ごとの説明を出すため）。定義にないキー（`RESEND_API_KEY` など）は従来どおり。Phase 4.10 で Stripe も定義に入った。
- 従来の「アプリに埋め込まれる変数に秘密のキー」の項目は、定義で扱った変数については重ねて出さない（定義にないものは従来どおり）。

## 4. 公開前の仕上げ（2026-10-09）

- Supabase の新方式 `SUPABASE_SECRET_KEYS` を秘密、`SUPABASE_PUBLISHABLE_KEYS` を公開可能として追加した（旧方式の `SUPABASE_SERVICE_ROLE_KEY` は秘密、`SUPABASE_ANON_KEY` は公開可能のまま）。
- JSON などにまとめた値は、中の値ごとに分類して、いちばん重い分類だけを結果にする（値そのものは返さない）。
- ローカル開発用の鍵は、複数の根拠がそろったときだけ数えない（上の ※）。判断できなければ 🟠。
- GitHub のトークンは長さを固定しない（長い新形式も本物らしいと判断する）。乱数らしさの判定のうち「1234・abcd のような並び」は、短い値（60文字未満）だけで見るようにした（長い本物のトークンにも偶然入りうるため）。
- テストコードの API キー風のダミーは、`TEST_ONLY` / `DUMMY` / `NOT_REAL` を含む、明らかにテスト用と分かる値にした。本物の形式であることを確かめるテストの値は、従来どおりテストのたびに乱数で作り、コードには書かない。

## 5. テスト

`test/secret-names.test.ts` を作り直した。本物らしい値はテストのたびに乱数で作り、リポジトリに本物の秘密情報を置かない。

- 定義データの項目がそろっていること、各サービスの本物の形式が「本物らしい」と分類されること
- Supabase：publishable・anon を公開用の変数やソースに置いても 🔴・🟠 にならず、Supabase の診断（RLS）への案内は残ること／秘密キーの欄に anon キーが入っていても公開キーとして扱うこと／secret・service_role の公開用変数・Git 管理のソースへの直書きは 🔴／ローカル開発用の service_role はテスト用
- OpenAI・Anthropic・ElevenLabs・Claude Code・GitHub・Supabase：本物らしい直書き（tracked）→ 🔴（サービス名＋件数）／参照だけ・ダミー・ignore 済みの .env → 🔴 にならない
- 値の形での検出（sk-ant-・sb_secret_・ghp_・github_pat_）、OpenAI は名前がない場合は探さないこと
- GitHub Actions のシークレット参照、GitHub App の秘密鍵、DATABASE_URL の条件
- 定義にない名前（KEY・TOKEN・SECRET を含むだけ）は数えないこと
- 共通の重大度（tracked・untracked・ignored・Git なし・公開用の接頭辞）と、危険の項目に参照が混ざらないこと
- 分類名が「認証情報」になること、折りたたみの表示
- **すべての定義の値が、判定結果・チェック・画面のどこにも出ないこと**
