# Phase 2 報告：Security Advisor の結果を初心者向け診断に変換するロジック

実施日: 2026-10-07
範囲: 診断ロジックとCLIへの仮出力のみ。HTMLレポートのUI（Phase 3）には着手していない。

## 0. 完了条件の確認

```
Supabase Advisor Response ─ supabase/normalize.ts ─▶ AdvisorFinding[]（API非依存の共通型）
                          ─ diagnostics/classify.ts ─▶ Diagnostic[]（日本語・3段階分類）＋ DiagnosticReport
```

- モックの応答から日本語の `Diagnostic[]` まで変換できる。
  - 入口の関数：`diagnoseAdvisorResponse(body)`（通信なし）
- CLIで中身を確認できる。
  - `npm run preview`：同梱のサンプルを表示する。
  - `node dist/cli/preview.js <file.json>`：保存した応答を表示する。
  - 表示項目：危険度、日本語タイトル、日本語の説明、公開前に直すべきか、修正方針、AI修正指示。
- 実APIを使う流れ（`npm run poc`）も、日本語の診断結果を表示するように変更した。
  - `--raw`：実APIの応答を保存し、後で `preview` で再表示できる。
  - `--json`：診断結果をJSONで出力する。

### Phase 1 から変えた仕様
| 項目 | 変更内容 |
|---|---|
| プロジェクトの指定 | **標準フローでは、ダッシュボードのURLかプロジェクトIDを入力してもらう**。一覧から選ぶ方式は `--list-projects` を付けたときだけ使う（コードは残してある） |
| 必要な権限 | 標準は、対象プロジェクトの **Advisors: Read** のみ |
| Legacy PAT | 使用は許可する。`describeToken()` が `{kind, isBroadAccess, noticeJa}` を返し、`DiagnosticReport.token` に入れる。Phase 3 で警告表示に使える |
| 応答の検証 | 1件の異常で全体を失敗にしないよう変更した。読めない項目は飛ばし、未知の `level` は項目を残したうえで、どちらも `parseIssues` に記録する。記録があればレポートを「不完全」として扱う。**これに合わせて Phase 1 のテスト1件の期待値を変更した**（未知のlevel：エラー → 項目を残して記録） |

---

## 1. 対応した Advisor 項目一覧（38項目）と 2. 独自の分類 と 3. 公式の重要度との差

「状態」の列：確認済み＝公式OpenAPIの一覧に載っている。未確認＝診断SQL（splinter）にはあるが、OpenAPIの一覧に載っておらず、APIが返すかどうか確認できていない。

### 🔴 危険（9項目）
| Advisor | 公式 | 差 | 状態 | 分類の理由（要約） |
|---|---|---|---|---|
| `rls_disabled_in_public` | ERROR | 同じ | 確認済み | 公開用キー（anonキー）だけで全行を読み書きできる可能性がある |
| `policy_exists_rls_disabled` | ERROR | 同じ | 確認済み | Policyを作っていても適用されていない |
| `rls_references_user_metadata` | ERROR | 同じ | 確認済み | 権限の判定を、ユーザー本人が書き換えられる情報で行っている |
| `security_definer_view` | ERROR | 同じ | 確認済み | 元のテーブルのRLSを迂回できる |
| `auth_users_exposed` | ERROR | 同じ | 確認済み | ユーザーのメールアドレス等がAPIから見える |
| `leaked_service_key` | API応答に従う | — | 確認済み | 管理者用キーが漏洩している可能性がある |
| `insecure_queue_exposed_in_api` | ERROR | 同じ | 未確認 | キューを誰でも読み書きできる |
| `sensitive_columns_exposed` | ERROR | 同じ | 未確認 | 個人情報らしき列がRLSなしで見える |
| `rls_policy_always_true` | WARN | **引き上げ** | 未確認 | 追加・更新・削除を無条件で許可していて、RLSが実質的に無効 |

### 🟠 要確認（10項目＋未知の項目）
| Advisor | 公式 | 差 | 状態 | 分類の理由（要約） |
|---|---|---|---|---|
| `rls_enabled_no_policy` | INFO | **引き上げ** | 確認済み | **全アクセスが拒否される安全側の状態なので、危険にはしない**。ただし、アプリが動かない原因になり、回避策として service_role キーをブラウザ側に置く事故につながりやすい |
| `materialized_view_in_api` | WARN | 同じ | 確認済み | RLSが効かない。公開データとして意図的に置くこともある |
| `foreign_table_in_api` | WARN | 同じ | 確認済み | 同上 |
| `ssl_not_enforced` | API応答に従う | — | 確認済み | 直接接続の盗聴リスクがある。APIを通したアクセスには影響しない |
| `vulnerable_postgres_version` | API応答に従う | — | 確認済み | アップグレードが推奨される |
| `fkey_to_auth_unique` | ERROR | **引き下げ** | 未確認 | データ漏洩ではなく、Supabaseのauth更新時に障害の原因になる保守性の問題 |
| `anon_security_definer_function_executable` | WARN | 同じ | 未確認 | ログインしていない人が、RLSを迂回できる関数を実行できる。公開機能として意図的な場合もある |
| `authenticated_security_definer_function_executable` | WARN | 同じ | 未確認 | 誰でも新規登録できるアプリでは、実質的に誰でも実行できる |
| `pg_graphql_anon_table_exposed` | WARN | 同じ | 未確認 | テーブル名や列名が見える。行を読めるかはRLS次第 |
| `public_bucket_allows_listing` | WARN | 同じ | 未確認 | 他人がアップロードしたファイルの名前が分かる |
| *未知の項目* | — | — | — | 「参考」として表示するが、公開前の判定は「要確認」にし、総合結果も「確認をおすすめ」にする |

### 🔵 参考（14項目）
| Advisor | 公式 | 差 | 状態 | 分類の理由（要約） |
|---|---|---|---|---|
| `function_search_path_mutable` | WARN | **引き下げ** | 確認済み | 悪用には、攻撃者がDB内にオブジェクトを作れる前提が必要。修正は簡単なので推奨はする |
| `extension_in_public` | WARN | **引き下げ** | 確認済み | 構成上の問題で、すぐに漏洩につながるものではない |
| `unsupported_reg_types` | WARN | **引き下げ** | 確認済み | 漏洩ではなく、アップグレードを妨げる要因 |
| `pg_graphql_authenticated_table_exposed` | WARN | **引き下げ** | 未確認 | ログインユーザーにテーブルが見えるのは一般的 |
| `extension_versions_outdated` | WARN | **引き下げ** | 未確認 | 直ちに公開を止める理由ではない |
| `auth_leaked_password_protection`、`auth_otp_long_expiry`、`auth_otp_short_length`、`auth_insufficient_mfa_options`、`auth_password_policy_missing`、`password_requirements_min_length` | API応答に従う | — | 確認済み | 認証設定の改善提案 |
| `network_restrictions_not_set`、`pitr_not_enabled`、`log_connections_not_enabled` | API応答に従う | — | 確認済み | 追加の防御策・バックアップ・監査ログの設定 |

### 診断自体が実行できなかったことを表す項目（5項目、参考＋「不完全」扱い）
`advisor_check_unavailable`、`project_not_active`、`db_not_reachable`、`db_connection_failing`、`instance_db_down`
→ 公開前の判定は「要確認」にする。`affectsCompleteness: true` を付け、レポート全体を `incomplete` にして、「0件＝安全」と誤解させないようにする。

各項目の詳しい分類理由は、`src/explanations/definitions.ts` の `severityReason` に書いてある（公式と分類が違う項目は、理由に必ず「公式は〜」と書くことをテストで確認している）。

## 4. 未対応の Advisor

| 項目 | 理由 | 実際に返った場合の扱い |
|---|---|---|
| `no_backup_admin` | 公式の意味を資料で確認できなかった（OpenAPIに名前しかない） | 未知の項目として、公式の英語の説明とヘルプURL付きで表示する |
| `db_connection_limit_reached`、`instance_telemetry_lost`、`instance_alert_firing`、`log_*_error_rate_high`（4種類） | 稼働状態（HEALTH）の監視項目で、セキュリティの指摘ではない | カテゴリがSECURITYでなければ除外し、件数を `excludedCount` に数える |
| `unindexed_foreign_keys`、`auth_rls_initplan`、`no_primary_key`、`unused_index`、`multiple_permissive_policies`、`duplicate_index`、`table_bloat`、`autovacuum_disabled` | パフォーマンス（PERFORMANCE）の項目 | 同上（除外） |

新しい項目を追加するときは、`diagnosticDefinitions` に1件足すだけで済む。

## 5. AI修正プロンプトの生成方式

- **外部のAI APIは使わず、固定テンプレートを組み合わせて作る**（`src/explanations/prompt.ts`）。`diagnostics/`、`explanations/`、`types/` に通信処理やAI APIの呼び出しがないことも、テストで確認している。
- 構成（全項目で共通）：
  1. 前置き：対象、Advisor名、公式の英語の指摘文、公式の解説URL
  2. **お願いしたいこと**：項目ごとの `prompt.task`
  3. **変更する前に、まず確認してほしいこと**：以下の4つは全項目に必ず入れる。必要に応じて項目固有の確認を追加する。
     - 現在のSchema
     - 既存のRLS Policy・権限設定
     - 認証方式（Supabase Authを使っているか、ログインせずに使える画面があるか、service_roleキーをどこで使っているか）
     - アプリ側のアクセス要件
  4. **守ってほしいこと**：以下は共通で入れ、項目固有の注意も追加する（例：漏洩キーの値を出力しない）。
     - 既存機能を壊さないこと
     - 推測だけで変更しないこと（要件が分からなければ、変更前に説明して確認を取ること）
     - 変更はマイグレーションとして残し、本番DBへ直接SQLを実行しないこと
     - service_role キーで回避しないこと
  5. **最後に説明してほしいこと**：何を変更したか、なぜ必要だったか、確認すべきテスト（ログインしていない状態・別のユーザーでの確認を含む）
- 項目ごとの違いは、定義データの `task`、`extraChecks`、`extraRules` だけで表す。文面の `{target}` などの穴埋めはローカルで行う。
- 公式の英語の指摘文は、制御文字を取り除き、500文字までに切り詰めてから埋め込む（テーブル名などはユーザー自身が付けたものだが、念のため）。

## 6. テスト結果

`npm test`：**57件すべて通過**（Node 22）。Phase 1 のクライアントのテスト19件と、Phase 2 の診断のテスト38件。

| 指示書のテスト項目 | 対応するテスト |
|---|---|
| 既知のAdvisorが正しい診断に変換される | rls_disabled_in_public の全項目／主要10項目の分類／ビューの表示 |
| 公式と独自の分類が違う項目 | 5項目（INFO→要確認、WARN→参考、ERROR→要確認、WARN→危険、WARN→参考）／公式のlevelを変えても独自の分類が変わらないこと |
| RLS有効・Policyなし | 危険でない／「漏れる状態ではありません」と説明する／断定的な表現がない |
| 同じテーブルに複数の指摘 | 同じ resourceKey になりグループ化される／1件に潰さない／id を一意にする |
| 未知のAdvisor | 参考＋要確認になる／「問題がないという意味ではありません」と表示する／総合結果が「大きな指摘なし」にならない |
| observed_at あり／なし | 保持される／最新時刻と最古時刻／ない場合は undefined |
| リソース情報あり／なし | 代わりの言葉を使う／`advisor:<name>` でまとめる／**全定義について、あり／なしの両方で穴埋め漏れがない** |
| 不完全なAPIレスポンス | `lints` がない→null／壊れた項目は読み飛ばして不完全扱い／任意項目が欠けている／https以外のURLを拒否する／SECURITY以外を除外する／診断が実行できなかった項目 |
| 英語の公式説明を含むレスポンス | 日本語の説明に英語を混ぜない／英語は別のフィールドとプロンプトに残す／制御文字や長すぎる文の処理 |
| AI修正プロンプトの生成 | 必須の節と順番／**全定義と未知の項目に共通の確認事項が入る**／項目固有の追加 |
| その他 | 定義データに必須項目と理由がある／`status` がOpenAPIの掲載状況と一致する／総合結果・並び順・注意書き／0件でも「安全」と言わない／Legacyトークンの情報／同梱サンプル／診断ロジックに通信処理がない |

CLIの確認：`npm run preview` で、サンプル6件（危険2・要確認1・参考3。未知の項目1件を含む）を日本語で表示できることを確認した。

## 7. Phase 3 で必要になる変更

1. **HTMLの描画では、すべての文字列をエスケープする。** `titleJa` などにはテーブル名（ユーザーが付けた名前）が入る。`helpUrl` は https に限定済み。
2. 表示に使うデータは、すでに `DiagnosticReport` に揃っている。
   - 総合結果：`headlineJa` と `counts`
   - 結果の時点：`observedAt.latest` を使い、「この診断結果は○時点の…」と表示する
   - 注意書き：`disclaimerJa`
   - 警告：`incomplete`（不完全）、`unknownAdvisorNames`（未対応の項目）、`token.noticeJa`（Legacyトークン）
3. **同じ対象への指摘をまとめて表示する**ときは、`groups`（重い順、`diagnosticIds` 付き）を使う。カードを1枚にまとめるか、見出しの下に並べるかはUIで決める。
4. 詳細表示には、`officialTitle`、`officialDetail`、`severityReason`、`originalAdvisorData` を出す。通常の画面には出さない。
5. `definitionStatus: 'unconfirmed'` の項目は、表示上は区別しなくてよい（実際に返ってきた時点で、その項目は存在していると言えるため）。ただし、実APIで確認したら `status` を `confirmed` に更新する。
6. ISO形式の時刻（`observedAt`）を、日本時間の表示に整える。
7. コピーボタンは `aiFixPrompt` をそのまま使う。
8. 入口を `poc.ts` から本番用のCLIへ移す。トークン入力 → URL入力 → 取得 → レポートをローカルサーバーで配信 → ブラウザを起動、という流れにする。

## 8. Phase 1 で未確認だった3項目について新しく分かったこと

- **OpenAPIの一覧に載っていないのは、3項目だけではなかった。** splinter の lint 番号と照合すると、OpenAPIの一覧にあるのは番号0001〜0018までで、**0019以降の12項目はすべて載っていなかった**。
  - 欠けている項目には、セキュリティと関係ない `table_bloat`(0020) や `autovacuum_disabled`(0030) も含まれる。
  - つまり「3項目だけを意図的に外した」のではなく、**OpenAPIの一覧の更新が、ある時点で止まっている**可能性が高い（Phase 1 §5-2 の仮説 (a) を支持する材料）。
  - ただし、APIが実際に返すかどうかは**依然として未確認**。
- これを受けて、同じ「未確認」の扱いを、3項目以外の6項目にも付けた（`insecure_queue_exposed_in_api`、`fkey_to_auth_unique`、`extension_versions_outdated`、`pg_graphql_*` 2項目、`*_security_definer_function_executable` 2項目）。
- 3項目は、指示どおりMVPの必須項目にはしていない。ただし、APIがその `name` を返した場合にすぐ日本語で表示できるよう、定義（`status: 'unconfirmed'`）は用意してある。DBへの直接接続やパスワードの要求はしていない。
- 実APIでの確認方法は Phase 1 §7 と同じ。`npm run poc -- --raw > result.json` で応答を保存すれば、`node dist/cli/preview.js result.json` で日本語の表示もあわせて確認できる。

## 変更したファイル

```
src/types/advisor.ts, diagnostic.ts      共通型（新規）
src/supabase/normalize.ts                 API応答 → AdvisorFinding（新規。項目単位で寛容に検証）
src/supabase/client.ts, validate.ts       getSecurityAdvisors が SecurityAdvisorResult を返すよう変更
src/supabase/token.ts                     describeToken() を追加（Legacyの警告情報）
src/explanations/definitions.ts           Advisor名 → 診断定義の対応表（新規。38項目）
src/explanations/prompt.ts, template.ts   AI修正指示・穴埋め・整形（新規）
src/diagnostics/classify.ts, resource.ts, index.ts   分類・グループ化・レポート生成（新規）
src/cli/poc.ts                            標準フローをURL入力に変更し、診断結果を表示
src/cli/preview.ts, format.ts             オフラインでの確認用の表示（新規）
samples/security-advisors.sample.json     確認用サンプル（新規）
test/diagnostics.test.ts                  38件（新規）／test/client.test.ts を戻り値の変更に合わせて更新
```
