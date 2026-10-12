# Phase 1 技術検証レポート：認証 → Project取得 → Security Advisor取得

検証日: 2026-10-07
対象: `koukai-check/`（Phase 1 PoC）

## 0. 結論

- **想定していた方式は、公式APIで成立する見込み。** スクレイピングなどの非公式な手段は使わない。
  - 認証：Scoped Personal Access Token（PAT）を Bearer で送る。
  - プロジェクト取得：`GET /v1/projects`
  - 診断結果の取得：`GET /v1/projects/{ref}/advisors/security`
  - Supabase公式のMCPサーバー（`@supabase/mcp-server-supabase` v0.13.0、2026-09-17公開）の `get_advisors` ツールも、同じエンドポイントを使っている。
- **実APIでの動作確認はまだできていない。** この検証環境は、ネットワークポリシーで `api.supabase.com` と `supabase.com` への通信が遮断されていた（プロキシが「Host not in allowlist」を返した）。実Supabaseプロジェクトでの確認は、§7 の手順で手元のPCから行う必要がある。
- そのため、今回の検証は次の2つに基づいている。
  - 公式のOpenAPI仕様・公式ドキュメントの原稿・公式MCPサーバーのソースコード・Advisorの診断SQL（splinter）を読んで、仕様を確認した。
  - その仕様どおりに応答するモックサーバーを相手に、PoCのテスト19件をすべて通過させた。
- **MVPの設計に影響する問題が4つある**（詳しくは §5）。
  1. このエンドポイントは**experimental（実験的）**扱いで、仕様が変わったり廃止されたりする可能性がある。
  2. 優先的に扱いたい lint の一部（Sensitive columns、過度に緩い Policy、Public Bucket）が**OpenAPIの一覧に載っていない**。APIが実際に返すかどうかは、実APIでの確認が必要。
  3. 「Storage Policy関連」の診断は、公式のlintでは `public_bucket_allows_listing` の1種類しかない。
  4. プロジェクト一覧の取得には、**アカウント全体を対象にした権限**が必要になる。対象プロジェクトだけに絞った最小権限と両立させるには、UXの工夫が要る。

---

## 1. 実際に利用した公式API

| 用途 | エンドポイント | 状態 | 出典 |
|---|---|---|---|
| プロジェクト一覧 | `GET https://api.supabase.com/v1/projects` | 安定版 | OpenAPI `v1-list-all-projects` |
| Security Advisor | `GET https://api.supabase.com/v1/projects/{ref}/advisors/security` | **experimental**（「It is subject to change or removal in future versions」と明記） | OpenAPI `v1-get-security-advisors` |
| （予備）Advisorを今すぐ実行 | `POST https://api.supabase.com/v2/projects/{ref}/advisors/run` | 安定性の明記なし | OpenAPI v2 `v2-run-project-advisors` |

- `{ref}` は英小文字20文字（`^[a-z]+$`、長さは20固定）。
- Security Advisor には任意のクエリパラメータ `lint_type=sql` がある。指定するとSQL系のlintだけに絞られるとみられる。PoCでは指定していない。
- v2の `advisors/run` は、実行するlint名を指定して、その場で診断を実行するAPI。1回のリクエストで指定できるのは最大10件。v1が廃止されたときの代替候補になる。
- 出典：
  - `supabase/supabase` リポジトリの `apps/docs/spec/api_v1_openapi.json` と `api_v2_openapi.json`（master）
  - `@supabase/mcp-server-supabase@0.13.0` のソースマップに含まれる `getSecurityAdvisors()`

## 2. 必要な認証方式

- **Personal Access Token を `Authorization: Bearer <token>` で送る。** Management API は OAuth2 にも対応しているが、MVPでは使わない（理由は §5-5）。
- PATには2種類ある（公式ドキュメント「Personal Access Tokens」より）。

| 種類 | 見分け方 | 権限 | 扱い |
|---|---|---|---|
| **Scoped token** | `sbp_fc` で始まる | 選んだ組織・プロジェクト・権限だけ | **推奨。** ただし公式には「public alpha、段階的に提供中」とされている |
| Classic token（Legacy） | `sbp_` で始まる（`sbp_fc` 以外） | アカウントの全権限。今後作るプロジェクトにも及ぶ | 動作はするが、PoCでは警告を表示する |

- Scoped token に付けた権限は、**アカウント自身の権限を絞るだけ**で、それ以上の権限は与えない。そのため、アカウントのロールでAdvisorを見られない場合は、トークンを工夫しても取得できない。
- PoCでは、トークンを環境変数 `SUPABASE_ACCESS_TOKEN` から読む。設定されていなければ、画面に表示されない形で入力を受け付ける。トークンは保存しない。`SUPABASE_ACCESS_TOKEN` は Supabase CLI と同じ変数名なので、すでにCLIを使っている人はそのまま使える。

## 3. 必要な権限

公式ドキュメントの権限一覧と、OpenAPIの `x-fga-permissions` から確認した。

| 操作 | トークン作成画面での権限名 | APIの内部名 | OAuthスコープ |
|---|---|---|---|
| Security Advisor の取得 | **Advisors: Read**（プロジェクト単位） | `advisors_read` | `database:read` |
| プロジェクト一覧 | **Projects (account-wide): Read** | `projects_read` | `projects:read` |
| （参考）1つのプロジェクトの詳細 | Project Settings: Read | `project_admin_read` | `projects:read` |

**最小権限の構成**：対象プロジェクトだけに絞った **Advisors: Read** の1つ。
- Advisorsの権限ではDBの中身を読めない。もし漏れても、影響は「診断結果を見られる」ことに限られる。
- ただしこの構成では、プロジェクト一覧を取得できない（403になる）。ユーザーにプロジェクトIDかダッシュボードのURLを貼ってもらう必要がある。PoCは、403のときにこの入力へ自動的に切り替わる。
- 一覧から選ぶUXにしたい場合は、**Projects (account-wide): Read** も付けてもらう必要がある。この権限は、アカウントが参加しているプロジェクト名の一覧を読める。公式ドキュメントには「the projects the token can reach」と書かれているので、対象プロジェクトだけが返る可能性があるが、**未確認**。

## 4. 取得できるAdvisor情報

### 4-1. レスポンスの形（OpenAPIより）

```jsonc
{
  "lints": [
    {
      "name": "rls_disabled_in_public",          // lintの種類（ID）
      "title": "Sample: RLS is off for a public table",
      "level": "ERROR",                           // ERROR | WARN | INFO（公式の重要度）
      "facing": "EXTERNAL",
      "categories": ["SECURITY"],                 // SECURITY | PERFORMANCE | HEALTH
      "description": "Sample description ...",   // lint全体の説明（英語）
      "detail": "Sample detail: `public.profiles` is reachable from the API and RLS is off.", // 個別の指摘（英語・対象名入り）
      "remediation": "https://supabase.com/docs/guides/database/database-linter?lint=0013_rls_disabled_in_public", // 修正方法のURL
      "metadata": { "schema": "public", "name": "profiles", "type": "table" },       // 対象のリソース
      "cache_key": "rls_disabled_in_public_public_profiles",
      "observed_at": "2026-10-07T00:00:00Z"       // 任意項目
    }
  ]
}
```

- 必須項目：`name, title, level, facing, categories, description, detail, remediation, cache_key`。`metadata` と `observed_at` は任意。
- `metadata` の中身はlintによって違う。splinterの実装を見ると、OpenAPIに書かれていない項目も含まれる。
  - `sensitive_columns`（該当する列名）
  - `policy_name`、`qual`、`with_check`（**Policyの条件式のSQLそのもの**）
  - `bucket_id`、`policy_names`
  - `type: "bucket"`（OpenAPIの一覧にない値）
- 説明文はすべて英語。日本語化はこちらで用意する必要がある。

### 4-2. MVPで優先する項目と、公式lintの対応

公式lintの判定内容は、Advisorが内部で実行する診断SQLのリポジトリ `supabase/splinter`（`splinter.sql`）から確認した。

| 指示書の優先項目 | 対応する公式lint | 公式の重要度 | OpenAPIの一覧に載っているか |
|---|---|---|---|
| RLSが無効 | `rls_disabled_in_public` | ERROR | ✅ |
| | `policy_exists_rls_disabled`（Policyはあるのに RLSが無効） | ERROR | ✅ |
| RLSは有効だがPolicyがない | `rls_enabled_no_policy` | **INFO** | ✅ |
| 過度に緩いRLS Policy | `rls_policy_always_true`（`USING (true)` など） | WARN | ❌ **載っていない** |
| | `rls_references_user_metadata`（ユーザーが書き換えられる情報で判定している） | ERROR | ✅ |
| 認証なしでアクセスできるデータ | `rls_disabled_in_public`、`auth_users_exposed`、`security_definer_view`、`anon_security_definer_function_executable`、`pg_graphql_anon_table_exposed` | ERROR / WARN | 一部 ❌（後ろ2つ） |
| Sensitive columns の公開 | `sensitive_columns_exposed` | ERROR | ❌ **載っていない** |
| Public Storage Bucket | `public_bucket_allows_listing` | WARN | ❌ **載っていない** |
| Storage Policy関連 | （上の1種類のみ） | — | — |
| その他の重大項目 | `leaked_service_key`（service_role キーの漏洩）、`insecure_queue_exposed_in_api`、`fkey_to_auth_unique`、`vulnerable_postgres_version` など | ERROR / WARN | 一部 ❌ |

- OpenAPIにはSQL以外のlintも載っている。`auth_leaked_password_protection`、`leaked_service_key`、`ssl_not_enforced`、`pitr_not_enabled`、`network_restrictions_not_set` などで、`lint_type` を指定しなければこれらも返るとみられる。

## 5. MVP設計上の問題

### 5-1. Security Advisor APIが experimental 扱いである【影響：大】
仕様変更や廃止の可能性が公式に明記されている。
- 対策（PoCで実装済み）：
  - `supabase/` 以外のコードには正規化済みのデータだけを渡す。
  - 応答の形を実行時にチェックし、想定と違えば「API仕様変更の可能性」と日本語で案内する。
- 予備案：v2の `POST /v2/projects/{ref}/advisors/run`。必要な権限は同じだが、lint名を指定する方式で、1回あたり最大10件に制限される。

### 5-2. 優先項目の一部が、APIから返るかどうか未確認【影響：大】
Sensitive columns、緩いPolicy、Public Bucket の3つは、splinterには実装されているが、v1・v2どちらのOpenAPIの一覧にも載っていない。考えられる可能性は2つある。
- (a) APIは返しているが、OpenAPIの記載が遅れているだけ。
- (b) Management API経由では、まだ実行されていない。

**実APIで確かめる必要がある（§7）。** PoCは lint名を固定の一覧で弾かない作りにしてあるので、(a) ならそのまま対応できる。(b) の場合の代替案は次の2つで、どちらを選ぶかは判断が必要。
- 代替1：その3項目をMVPの対象から外す（推奨）。
- 代替2：ユーザーのDB接続情報を使い、splinterのSQLを手元で実行する。ただし**DBのパスワードが必要**になり、「読み取り専用・最小権限」という方針から大きく外れる。そのため推奨しない。

### 5-3. 「Storage Policy関連」の公式な診断はほぼない【影響：中】
公式lintでStorageを扱うのは `public_bucket_allows_listing` だけ。非公開bucketのPolicyが緩すぎる、といった問題は判定できない。独自にStorageを診断すると「独自スキャナーは作らない」という方針に反するので、**MVPでは「Public Bucketのファイル一覧が見える」の1項目に絞る**のが妥当。

### 5-4. 最小権限と、プロジェクト一覧から選ぶUXが両立しない【影響：中】
§3のとおり、一覧の取得にはアカウント全体を対象にした権限が必要。
- 推奨：トークンは **Advisors: Read（対象プロジェクトのみ）** にする。プロジェクトは「ダッシュボードのURLを貼り付ける」方式で選ぶ。PoCでは、ID、`/project/<ref>` を含むダッシュボードのURL、`https://<ref>.supabase.co` のどれでも受け付ける。
- 一覧の権限も付いているトークンなら、一覧から選べるようにする（PoCで実装済み）。

### 5-5. Scoped token は alpha 版で、作るのも初心者には難しい【影響：中】
- 段階的に提供中なので、まだ使えないアカウントがありうる。その場合は Classic token で動かすことになるが、全権限を持つトークンなので、警告を表示する（PoCで実装済み）。
- 権限を選ぶ画面は、初心者には分かりにくい。READMEに「Advisorsだけを Read にする」手順をスクリーンショット付きで載せる必要がある。
- OAuthで連携する方式（`database:read` スコープ）なら、トークンを作る手間はなくなる。ただし次の理由から、**MVPでは採用しない**。
  - OAuthアプリの登録と、client secret の管理が必要になる。
  - `database:read` は Advisors より広い権限である。
  - ブラウザから戻ってくる処理を受けるために、ローカルにHTTPサーバーを立てる必要がある。

### 5-6. 診断結果が最新でない可能性【影響：中】
`observed_at` という項目があることから、v1の結果は、定期的に実行された診断のキャッシュかもしれない。その場合、「直したのに、再実行しても指摘が消えない」という混乱が起きうる。実APIで、修正の直後に結果が変わるかを確認する。変わらない場合は、v2の `advisors/run`（その場で実行）を併用するか、UIで「結果の取得時刻」を表示する。

### 5-7. 公式の重要度と、指示書の「危険」の感覚がずれる【影響：小】
- `rls_enabled_no_policy` は公式ではINFO。実際、RLSが有効でPolicyがないテーブルは、**全員のアクセスが拒否される安全側の状態**で、データ漏洩ではない。「アプリが動かない」原因にはなる。
- `rls_policy_always_true` は公式ではWARNだが、更新・削除が誰でもできる状態なので、実質的には危険。
- そのため、公式の `level` を機械的に3段階へ変換するのではなく、**lint名ごとの対応表**で分類する（§6）。

### 5-8. 中継プロキシの403を「権限不足」と誤って案内する問題【影響：小・修正済み】
この検証環境で実際に起きた。プロキシが返す `text/plain` の403を、トークンの権限不足と取り違えていた。JSON以外の401/403は「ネットワーク・プロキシの問題」として案内するよう修正し、テストも追加した。会社のネットワークで使う人には現実に起こりうる。

### 5-9. 診断結果には機密に近い情報が含まれる【影響：小】
`metadata.qual` にはPolicyの条件式のSQLが、`detail` にはテーブル名や列名が含まれる。外部に送らないのは当然として、ターミナルやスクリーンショットで共有されることを想定する。通常の画面には生のデータを出さず、詳細表示に入れる。

## 6. 次の実装フェーズで変更すべき点

1. **実APIでの確認を最優先する（§7）。** 確認結果によって、§5-2の判断（3項目を残すか外すか）が決まる。
2. **重要度の対応表**（Phase 2の叩き台）

   | 独自の重要度 | lint名 |
   |---|---|
   | 🔴 危険 | `rls_disabled_in_public`、`policy_exists_rls_disabled`、`sensitive_columns_exposed`、`auth_users_exposed`、`rls_references_user_metadata`、`rls_policy_always_true`、`leaked_service_key`、`security_definer_view`、`insecure_queue_exposed_in_api` |
   | 🟠 要確認 | `public_bucket_allows_listing`、`anon_security_definer_function_executable`、`pg_graphql_anon_table_exposed`、`rls_enabled_no_policy`（安全側だが、意図した設定か確認が必要）、`authenticated_security_definer_function_executable`、`auth_leaked_password_protection`、`fkey_to_auth_unique` |
   | 🔵 参考 | 上記以外の SECURITY lint（`function_search_path_mutable`、`extension_in_public`、`materialized_view_in_api` など）、`ssl_not_enforced`、`pitr_not_enabled`、`network_restrictions_not_set` など |
   | 対応表にないもの | 公式の level で代わりに判定する（ERROR→危険、WARN→要確認、INFO→参考）。説明文は汎用のものを使い、公式ドキュメントへのリンクを付ける |

3. 同じ lint が複数のテーブルで出た場合は、**カードを1枚にまとめて対象を一覧表示する**。公式MCPサーバーの `groupAdvisorLints` と同じ考え方。同じテーブルについて `rls_disabled_in_public` と `sensitive_columns_exposed` が両方出たら、1枚のカードに統合する。
4. カテゴリが `SECURITY` 以外のもの（`HEALTH`、`PERFORMANCE`）は表示しない。
5. 認証の流れを「トークン入力 → ダッシュボードのURLを貼り付け」を基本にした案内へ変える（§5-4）。
6. レポートに「診断結果の取得時刻」を表示する（§5-6）。
7. Node.js の要件は 18.17 以上（標準の `fetch` と `AbortSignal.timeout` を使うため）。実行時に必要な依存パッケージは0個のままにして、利用者が依存パッケージ経由で攻撃を受けるリスクを最小にする。
8. `npx koukai-check` の本体は `src/cli/poc.ts` を置き換える形で作る。`supabase/` は今回のコードをそのまま使う。

## 7. 実APIでの確認手順（手元のPCで実施）

検証には、**捨ててもよいテスト用プロジェクト**を使う。

1. テスト用プロジェクトの SQL Editor で、意図的に問題のある状態を作る。
   ```sql
   create table public.kc_profiles (id uuid primary key, email text, phone text);   -- RLSなし＋個人情報の列
   create table public.kc_notes (id serial primary key, body text);
   alter table public.kc_notes enable row level security;                          -- RLSはあるがPolicyなし
   create table public.kc_posts (id serial primary key, body text);
   alter table public.kc_posts enable row level security;
   create policy "anyone can delete" on public.kc_posts for delete using (true);    -- 緩すぎるPolicy
   insert into storage.buckets (id, name, public) values ('kc-public', 'kc-public', true);
   create policy "kc list" on storage.objects for select using (bucket_id = 'kc-public'); -- Public bucketのファイル一覧
   ```
2. Account > Access Tokens で、Scoped token を2種類作る。
   - A：対象プロジェクトの **Advisors: Read** のみ。
   - B：Aに **Projects (account-wide): Read** を追加。
3. PoCを実行する。
   ```bash
   cd koukai-check && npm install
   SUPABASE_ACCESS_TOKEN=<A> npm run poc -- --json > result-A.json   # 一覧取得が403になり、URL入力に切り替わることを確認
   SUPABASE_ACCESS_TOKEN=<B> npm run poc                              # 一覧から選べるか、返るのは対象プロジェクトだけかを確認
   SUPABASE_ACCESS_TOKEN=invalid npm run poc                          # 無効なトークンの案内を確認
   ```
4. 次の点を確認する。
   - [ ] `result-A.json` に `sensitive_columns_exposed`、`rls_policy_always_true`、`public_bucket_allows_listing` が含まれるか（§5-2）。
   - [ ] トークンBで一覧に何件返るか（§3）。
   - [ ] 問題を直した直後に再実行して、結果が変わるか（§5-6）。
   - [ ] SQL以外のlint（`auth_leaked_password_protection` など）が返るか。
   - [ ] Advisors権限のないトークンで403になるか。

結果のJSONにはテーブル名などが含まれる。共有するときは、テスト用プロジェクトのものだけにすること。

## 8. PoCの内容とテスト結果

```
koukai-check/
  src/supabase/  client.ts（APIクライアント・通信先は固定）, validate.ts（応答の形チェック）,
                 errors.ts（エラーの分類）, token.ts（トークン種別の判定）, types.ts
  src/cli/       poc.ts（入口）, prompt.ts（入力内容を表示しない入力）, project-ref.ts（URLからIDを抽出）, messages.ts（日本語のエラー案内）
  test/          client.test.ts, fixtures.ts
```

`npm test` で19件のテストがすべて通過した（Node 22・ローカルのモックサーバー相手）。
- 正常系：プロジェクトが1件／複数、Advisorの結果が5件／0件。OpenAPIの一覧にない lint名や metadata も保持されること。
- 異常系：無効なトークン(401)、権限不足(403、一覧／Advisorそれぞれ)、429、500、JSONでない応答、`lints` がない、未知の `level`、接続できない、プロキシの403。
- セキュリティ：
  - 不正なプロジェクトIDは通信する前に弾く（パスを細工する攻撃を防ぐ）。
  - トークンはヘッダーでのみ送り、URLには含めない。
  - 既定の通信先は `api.supabase.com` だけ。接続先を環境変数で変える手段は意図的に用意していない。
- 補助関数：URLからIDを抽出する処理（ドメインの偽装は拒否する）、トークン種別の判定、全種類のエラーに日本語の案内があること。

実行時に必要な依存パッケージは0個。開発用に使うのは `typescript` と `@types/node` だけ。テレメトリの送信や外部への通信のコードはない。

## 出典
- Supabase Management API OpenAPI v1: `https://raw.githubusercontent.com/supabase/supabase/master/apps/docs/spec/api_v1_openapi.json`
- 同 v2: `.../apps/docs/spec/api_v2_openapi.json`
- Personal Access Tokens（ドキュメントの原稿）: `.../apps/docs/content/guides/platform/personal-access-tokens.mdx`
- Scoped PAT の権限一覧: `.../apps/docs/content/_partials/access-control/scoped_pat_permissions.mdx`、`scoped_pat_mcp_tools.mdx`
- Advisorの診断SQL: `https://raw.githubusercontent.com/supabase/splinter/main/splinter.sql`
- Supabase公式MCPサーバー: npm `@supabase/mcp-server-supabase@0.13.0`（`getSecurityAdvisors`、`groupAdvisorLints`）
