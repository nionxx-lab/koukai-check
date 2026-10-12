# 実Supabase API を使った E2E 確認チェックリスト

公開前に**必ず**行う確認です。開発に使ったクラウド環境からは `api.supabase.com` に接続できなかったため、ここに書いた項目は**まだ1つも実施されていません**。
すべての必須項目が ✅ になるまで、Phase 4 の判定は「条件付き公開可能：実API確認待ち」のままです。

- 実施日：＿＿＿＿　実施者：＿＿＿＿
- OS / 端末：＿＿＿＿　Node.js：`node --version` ＝ ＿＿＿＿
- 確認したビルド：`koukai-check-0.1.0.tgz`（`npm pack` で作ったもの）／ git commit ＿＿＿＿

> 結果の欄には、✅（期待どおり）／❌（期待と違う）／—（未実施）と、気づいたことを書いてください。
> **トークンの値やスクリーンショット内のトークンは、このファイルに書かないでください。**

---

## 0. 準備

```bash
cd koukai-check
npm install
npm test                      # 189件すべて通ることを確認
npm pack                      # koukai-check-0.1.0.tgz ができる
```

以降は、公開後の `npx koukai-check` に近い形にするため、作った tarball から起動します。

```bash
npx --yes --package ./koukai-check-0.1.0.tgz koukai-check
```

---

> **画面からの流れ（主な入口）も確認してください。** `npx --yes --package ./koukai-check-0.1.0.tgz koukai-check` で画面を開き、テスト用プロジェクトのアプリのフォルダ（`.env` に `SUPABASE_URL` があるもの）を選んで、「Supabase のチェックを始める」から 3-5 以降と同じ項目を確認します。
> 下の 3 章の手順は、開発用CLI（`koukai-check supabase`）での確認です。

## 1. テスト用の Supabase プロジェクトを作る

| # | 手順 | 結果 |
|---|---|---|
| 1-1 | 本番とは別に、**捨ててもよい**テスト用プロジェクトを作成する | |
| 1-2 | SQL Editor で、下の SQL を実行して「問題のある状態」を作る | |

```sql
-- RLS が無効なテーブル（個人情報らしき列つき）
create table public.kc_profiles (id uuid primary key default gen_random_uuid(), email text, phone text);
-- RLS は有効だが Policy がないテーブル
create table public.kc_notes (id serial primary key, body text);
alter table public.kc_notes enable row level security;
-- 条件が常に成立する Policy（更新・削除を誰でもできる）
create table public.kc_posts (id serial primary key, body text);
alter table public.kc_posts enable row level security;
create policy "kc anyone can delete" on public.kc_posts for delete using (true);
-- 作成者の権限で動くビュー
create view public.kc_profile_view with (security_invoker = false) as select id, email from public.kc_profiles;
-- 公開バケットとファイル一覧のPolicy
insert into storage.buckets (id, name, public) values ('kc-public', 'kc-public', true);
create policy "kc list" on storage.objects for select using (bucket_id = 'kc-public');
```

## 2. トークンを作る

| # | 手順 | 結果 |
|---|---|---|
| 2-1 | https://supabase.com/dashboard/account/tokens で **Scoped token** を作る（`sbp_fc` で始まる） | |
| 2-2 | 対象は**テスト用プロジェクトだけ**、権限は **Advisors: Read だけ**にする | |
| 2-3 | 別に、**Advisors の権限を付けない** Scoped token（例：Project Settings: Read だけ）を作る（権限不足の確認用） | |
| 2-4 | （任意）Legacy（Classic）token を用意する。確認が終わったらすぐ削除する | |
| 2-5 | Scoped token をまだ作れないアカウントの場合は、その旨を記録する | |

## 3. 基本の流れ（必須）

| # | 確認すること | 期待する結果 | 結果 |
|---|---|---|---|
| 3-1 | `npx --yes --package ./koukai-check-0.1.0.tgz koukai-check supabase` で起動する | 「AIで作ったSupabaseアプリを公開する前に…」と表示される | |
| 3-2 | テスト用プロジェクトのダッシュボードURLを貼り付ける | 受け付けられる（再入力にならない） | |
| 3-3 | 2-1 のトークンを**貼り付ける** | **画面に文字が表示されない** | |
| 3-4 | 待つ | 「Supabaseの設定を確認しています...」のあと、ブラウザが自動で開く | |
| 3-5 | レポートの最上部 | 「修正してから公開することをおすすめします」と、危険の件数が1件以上 | |
| 3-6 | `kc_profiles` の「RLS（データへのアクセス制限）が無効です」が **🔴 危険** に表示される | 表示される | |
| 3-7 | `kc_notes` の「RLSが有効ですが、Policyがありません」が **🟠 要確認**（危険ではない） | 表示される | |
| 3-8 | `kc_profile_view` の「作成者の権限でデータを読み出す設定」が表示される | 表示される | |
| 3-9 | 「AIに修正を頼む指示をコピー」を押す | 「コピーしました」と表示され、エディタに貼り付けると指示文が入る | |
| 3-10 | 「Supabase公式の解説を開く」 | supabase.com のページが新しいタブで開く | |
| 3-11 | 「診断結果の取得時刻」 | 日本時間で表示される。実行時刻と大きくずれていない | |
| 3-12 | ターミナルで Ctrl+C | 「終了しました。」と表示されて終了する。ブラウザのページは残る | |

## 4. 修正して再診断（必須）

| # | 確認すること | 期待する結果 | 結果 |
|---|---|---|---|
| 4-1 | `alter table public.kc_profiles enable row level security;` を実行する | | |
| 4-2 | すぐに再実行する | `kc_profiles` の「RLSが無効」が消え、代わりに「RLSが有効ですが、Policyがありません」が出る | |
| 4-3 | 4-2 で結果が変わらなかった場合、何分後に変わったか | 変わるまでの時間：＿＿＿分（結果がキャッシュされているかの確認） | |

## 5. エラーの扱い（必須）

| # | 確認すること | 期待する結果 | 結果 |
|---|---|---|---|
| 5-1 | 存在しないトークン（`sbp_fc_invalid` など）を入力する | 「アクセストークンが無効です」と表示され、再入力を求められる | |
| 5-2 | 2-3 の権限不足トークンを入力する | 「Advisors」を Read にするよう案内される | |
| 5-3 | 5-1・5-2 で、実際に返ったHTTPステータス（`KOUKAI_CHECK_DEBUG=1` を付けて実行すると確認できる） | 401 / 403 のどちらだったか：＿＿＿／＿＿＿ | |
| 5-4 | 自分がアクセスできない、または存在しないプロジェクトIDを入力する（例：`aaaaaaaaaaaaaaaaaaaa`） | 「プロジェクトが見つかりません」か「権限がありません」。実際のステータス：＿＿＿ | |
| 5-5 | ネットワークを切って実行する | 「Supabaseに接続できませんでした」と表示される | |
| 5-6 | `npx … koukai-check supabase --token sbp_xxx` と実行する | 拒否され、トークンを作り直すよう案内される（値は表示されない） | |

## 6. Legacy トークン（任意だが推奨）

| # | 確認すること | 期待する結果 | 結果 |
|---|---|---|---|
| 6-1 | Legacy token で実行する | ターミナルとレポートの両方に「このトークンは広い権限を持っています。」と表示される | |
| 6-2 | 確認後、Legacy token をダッシュボードで削除した | | |

## 7. 実APIの応答の確認（必須）

レポートの「技術的な詳細を見る」→「Supabaseから返された元データ」で確認できます。

| # | 確認すること | 結果 |
|---|---|---|
| 7-1 | `observed_at` が含まれているか（形式：例 `2026-10-07T09:00:00Z`） | あり／なし、形式：＿＿＿ |
| 7-2 | `sensitive_columns_exposed`（個人情報らしき列）が返ったか | 返った／返らない |
| 7-3 | `rls_policy_always_true`（kc_posts の Policy）が返ったか | 返った／返らない |
| 7-4 | `public_bucket_allows_listing`（kc-public）が返ったか | 返った／返らない |
| 7-5 | `security_definer_view` の `metadata.type` が `view` か | |
| 7-6 | 「Supabaseから新しい診断項目が返されました」というカードが出たか。出た場合は項目名 | 項目名：＿＿＿ |
| 7-7 | 認証設定の項目（`auth_leaked_password_protection` など）が返ったか | |
| 7-8 | 日本語の説明に、不自然な対象名（記号の混入など）がないか | |

> 7-2〜7-4 と 7-6 の結果は、`src/explanations/definitions.ts` の `status`（`unconfirmed` → `confirmed`）の更新に使います。

## 8. 片付け

| # | 手順 | 結果 |
|---|---|---|
| 8-1 | テストで作ったトークンを、すべてダッシュボードで削除した | |
| 8-2 | テスト用プロジェクトを削除した（または一時停止した） | |
| 8-3 | 保存したレポートHTMLを、共有しない場所に移した／削除した | |

---

## 実施記録（2026-10-08、Windows 実機）

利用者が Windows 実機で、実際の Supabase API を使って確認した。起動方法は Windows の exe 版（Phase 4.7 の専用ウィンドウ）で、画面の「Supabase のチェックを始める」から実行した。

| 確認したこと | 対応する項目 | 結果 |
|---|---|---|
| RLS を無効にしたテーブルがある状態でチェック | 3-5・3-6 | ✅ **🔴 危険が1件**表示された |
| そのテーブルの RLS を有効にし、Policy を作らずに再チェック | 4-1・4-2 | ✅ **🟠 要確認が1件**表示された（危険ではない） |
| テスト用のテーブルを削除して再チェック | （追加の確認） | ✅ **すべて0件**になった |

これで、**実 API を使った基本の流れ（危険の検出 → 修正後の再診断 → 指摘がなくなること）は確認済み**とする。

報告に含まれていないため、個別には記録していない項目：
- 5（無効なトークン・権限不足・存在しないプロジェクトのときの表示と、実際のHTTPステータス）
- 6（Legacy トークン）
- 7（元データの `observed_at` の形式、未確認の項目〈`sensitive_columns_exposed`・`rls_policy_always_true`・`public_bucket_allows_listing` など〉が返るかどうか）
- 4-3（結果が変わるまでの時間）

7 の結果がないため、`src/explanations/definitions.ts` の `status: 'unconfirmed'` の項目は、未確認のまま変えていない。

---

## 判定

- [x] 実 API を使った基本の流れ（3・4 の主要な項目）が ✅（2026-10-08、Windows 実機）
- [ ] 5・7 の個別の結果の記録（任意。記録できたら、未確認の項目の status を更新する）
- [ ] ❌ がある場合は、内容を GitHub Issue 等に記録し、修正してから再確認した

すべて満たしたら、Phase 4 の判定を「公開可能」に更新できます。
