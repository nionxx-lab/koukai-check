import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildDiagnosticReport, toDiagnostic } from '../src/diagnostics/classify.js';
import { diagnoseAdvisorResponse } from '../src/diagnostics/index.js';
import { diagnosticDefinitions } from '../src/explanations/definitions.js';
import { normalizeSecurityAdvisors } from '../src/supabase/normalize.js';
import { describeToken } from '../src/supabase/token.js';
import type { AdvisorFinding } from '../src/types/advisor.js';
import type { Diagnostic, DiagnosticReport } from '../src/types/diagnostic.js';
import { LINTS_WITH_ISSUES } from './fixtures.js';

// Supabase Management API OpenAPI（api_v1_openapi.json）の lint name enum（2026-10-07 時点）
const OPENAPI_LINT_NAMES = new Set([
  'unindexed_foreign_keys', 'auth_users_exposed', 'auth_rls_initplan', 'no_primary_key', 'unused_index',
  'multiple_permissive_policies', 'policy_exists_rls_disabled', 'rls_enabled_no_policy', 'duplicate_index',
  'security_definer_view', 'function_search_path_mutable', 'rls_disabled_in_public', 'extension_in_public',
  'rls_references_user_metadata', 'materialized_view_in_api', 'foreign_table_in_api', 'unsupported_reg_types',
  'auth_otp_long_expiry', 'auth_otp_short_length', 'ssl_not_enforced', 'log_connections_not_enabled',
  'network_restrictions_not_set', 'password_requirements_min_length', 'pitr_not_enabled',
  'auth_leaked_password_protection', 'auth_insufficient_mfa_options', 'auth_password_policy_missing',
  'leaked_service_key', 'no_backup_admin', 'vulnerable_postgres_version', 'db_not_reachable',
  'db_connection_failing', 'db_connection_limit_reached', 'instance_telemetry_lost', 'instance_db_down',
  'instance_alert_firing', 'log_data_api_error_rate_high', 'log_auth_error_rate_high',
  'log_storage_error_rate_high', 'log_edge_function_error_rate_high', 'project_not_active',
  'advisor_check_unavailable',
]);

type RawLint = Record<string, unknown>;

function lint(name: string, overrides: RawLint = {}): RawLint {
  return {
    name,
    title: name,
    level: 'WARN',
    facing: 'EXTERNAL',
    categories: ['SECURITY'],
    description: `Description of ${name}`,
    detail: `Detail of ${name}`,
    remediation: `https://supabase.com/docs/guides/database/database-linter?lint=${name}`,
    metadata: { schema: 'public', name: 'profiles', type: 'table' },
    cache_key: `${name}_public_profiles`,
    ...overrides,
  };
}

function report(lints: unknown[]): DiagnosticReport {
  const r = diagnoseAdvisorResponse({ lints });
  assert.ok(r);
  return r;
}

function single(raw: RawLint): Diagnostic {
  const d = report([raw]).diagnostics[0];
  assert.ok(d);
  return d;
}

const ALL_TEXT_FIELDS: (keyof Diagnostic)[] = ['titleJa', 'explanationJa', 'remediationJa', 'aiFixPrompt'];

function assertNoPlaceholders(d: Diagnostic) {
  for (const field of ALL_TEXT_FIELDS) {
    const text = String(d[field]);
    assert.doesNotMatch(text, /\{(target|name|sensitiveColumns)\}/, `${d.advisorName}.${field} に未置換のプレースホルダ`);
    assert.ok(text.length > 0, `${d.advisorName}.${field} が空`);
  }
}

describe('既知の Advisor の変換', () => {
  it('rls_disabled_in_public → 危険・日本語の説明・修正指示', () => {
    const d = single(lint('rls_disabled_in_public', { level: 'ERROR', observed_at: '2026-10-07T09:00:00Z' }));
    assert.equal(d.severity, 'danger');
    assert.equal(d.shouldFixBeforeRelease, 'yes');
    assert.equal(d.officialSeverity, 'ERROR');
    assert.equal(d.definitionStatus, 'confirmed');
    assert.equal(d.titleJa, '`public.profiles` テーブルで、データへのアクセス制限（RLS）が無効です');
    assert.match(d.explanationJa, /誰がどの行を読んだり変更したりできるかを制限する仕組み/);
    assert.match(d.remediationJa, /Policyとセットで変更/);
    assert.equal(d.resourceType, 'table');
    assert.equal(d.resourceName, 'profiles');
    assert.equal(d.resourceKey, 'relation:public.profiles');
    assert.equal(d.helpUrl, 'https://supabase.com/docs/guides/database/database-linter?lint=rls_disabled_in_public');
    assert.equal(d.observedAt, '2026-10-07T09:00:00Z');
    assertNoPlaceholders(d);
  });

  it('権限境界・設定系の主要項目が想定どおりに分類される', () => {
    const expected: Record<string, Diagnostic['severity']> = {
      security_definer_view: 'danger',
      auth_users_exposed: 'danger',
      rls_references_user_metadata: 'danger',
      policy_exists_rls_disabled: 'danger',
      leaked_service_key: 'danger',
      function_search_path_mutable: 'info',
      extension_in_public: 'info',
      materialized_view_in_api: 'review',
      foreign_table_in_api: 'review',
      ssl_not_enforced: 'review',
    };
    for (const [name, severity] of Object.entries(expected)) {
      assert.equal(single(lint(name)).severity, severity, name);
    }
  });

  it('ビューの対象は「ビュー」と表示する', () => {
    const d = single(lint('security_definer_view', { metadata: { schema: 'public', name: 'user_stats', type: 'view' } }));
    assert.match(d.titleJa, /`public\.user_stats` ビュー/);
    assert.equal(d.resourceKey, 'relation:public.user_stats');
  });
});

describe('公式Severityと独自Severityの違い', () => {
  const cases: [string, 'ERROR' | 'WARN' | 'INFO', Diagnostic['severity']][] = [
    ['rls_enabled_no_policy', 'INFO', 'review'],
    ['function_search_path_mutable', 'WARN', 'info'],
    ['fkey_to_auth_unique', 'ERROR', 'review'],
    ['rls_policy_always_true', 'WARN', 'danger'],
    ['unsupported_reg_types', 'WARN', 'info'],
  ];
  for (const [name, official, own] of cases) {
    it(`${name}: 公式 ${official} → 独自 ${own}（理由つき）`, () => {
      const d = single(lint(name, { level: official }));
      assert.equal(d.officialSeverity, official);
      assert.equal(d.severity, own);
      assert.match(d.severityReason, /公式/);
    });
  }

  it('公式 level を変えても独自分類は変わらない（機械変換していない）', () => {
    for (const level of ['ERROR', 'WARN', 'INFO']) {
      assert.equal(single(lint('rls_disabled_in_public', { level })).severity, 'danger');
      assert.equal(single(lint('rls_enabled_no_policy', { level })).severity, 'review');
    }
  });
});

describe('RLS有効・Policyなし', () => {
  it('危険にせず、アクセス拒否の安全側の状態であることを説明する', () => {
    const d = single(lint('rls_enabled_no_policy', { level: 'INFO', metadata: { schema: 'public', name: 'notes', type: 'table' } }));
    assert.notEqual(d.severity, 'danger');
    assert.equal(d.severity, 'review');
    assert.equal(d.shouldFixBeforeRelease, 'review');
    assert.match(d.titleJa, /誰もアクセスできない状態/);
    assert.match(d.explanationJa, /データが外部に漏れる状態ではありません/);
    assert.match(d.explanationJa, /service_role/);
    assert.doesNotMatch(d.explanationJa, /漏洩します|危険です/);
    assert.match(d.aiFixPrompt, /不要な場合は変更せず/);
  });
});

describe('同一リソースへの複数の指摘', () => {
  it('同じテーブルの指摘は同じ resourceKey になり、グループにまとまる', () => {
    const r = report([
      lint('rls_disabled_in_public', { level: 'ERROR' }),
      lint('sensitive_columns_exposed', {
        level: 'ERROR',
        metadata: { schema: 'public', name: 'profiles', type: 'table', sensitive_columns: ['email', 'phone'] },
      }),
      lint('rls_enabled_no_policy', { level: 'INFO', metadata: { schema: 'public', name: 'notes', type: 'table' } }),
    ]);
    assert.equal(r.diagnostics.length, 3, '1件に潰さない');
    const profiles = r.groups.find((g) => g.resourceKey === 'relation:public.profiles');
    assert.ok(profiles);
    assert.equal(profiles.diagnosticIds.length, 2);
    assert.equal(profiles.severity, 'danger');
    assert.equal(r.groups[0]?.resourceKey, 'relation:public.profiles', '重いグループが先');

    const sensitive = r.diagnostics.find((d) => d.advisorName === 'sensitive_columns_exposed');
    assert.equal(sensitive?.definitionStatus, 'unconfirmed');
    assert.match(sensitive?.explanationJa ?? '', /該当しそうな列: email, phone/);
  });

  it('同じ id になる指摘は一意化する', () => {
    const r = report([lint('rls_disabled_in_public'), lint('rls_disabled_in_public')]);
    const ids = r.diagnostics.map((d) => d.id);
    assert.equal(new Set(ids).size, 2);
  });
});

describe('未知の Advisor', () => {
  it('クラッシュせず、参考・要確認の汎用診断にする（安全と断定しない）', () => {
    const r = report([lint('some_future_lint', { level: 'ERROR', detail: 'Table `public.orders` triggered a new check.' })]);
    const d = r.diagnostics[0];
    assert.ok(d);
    assert.equal(d.severity, 'info');
    assert.equal(d.shouldFixBeforeRelease, 'review');
    assert.equal(d.definitionStatus, 'unknown');
    assert.match(d.titleJa, /Supabaseから新しい診断項目が返されました（some_future_lint）/);
    assert.match(d.explanationJa, /問題がないという意味ではありません/);
    assert.match(d.severityReason, /公式の重要度: ERROR/);
    assert.equal(d.officialDetail, 'Table `public.orders` triggered a new check.');
    assert.ok(d.helpUrl);
    assert.deepEqual(r.unknownAdvisorNames, ['some_future_lint']);
    assert.notEqual(r.overall, 'no-major-findings', '未知の項目があるときに「大きな指摘なし」にしない');
    assertNoPlaceholders(d);
  });
});

describe('observed_at', () => {
  it('あれば保持し、レポートに最新時刻を出す', () => {
    const r = report([
      lint('rls_disabled_in_public', { observed_at: '2026-10-07T09:00:00Z' }),
      lint('extension_in_public', { observed_at: '2026-10-07T10:00:00Z', metadata: { schema: 'public', name: 'pgcrypto', type: 'extension' } }),
    ]);
    assert.equal(r.observedAt.latest, '2026-10-07T10:00:00Z');
    assert.equal(r.observedAt.earliest, '2026-10-07T09:00:00Z');
    assert.ok(r.diagnostics.every((d) => d.observedAt));
  });

  it('なければ undefined のまま', () => {
    const r = report([lint('rls_disabled_in_public')]);
    assert.equal(r.diagnostics[0]?.observedAt, undefined);
    assert.deepEqual(r.observedAt, { earliest: undefined, latest: undefined });
  });
});

describe('リソース情報', () => {
  it('metadata がない場合は代替の言葉を使い、Advisor名でまとめる', () => {
    const d = single(lint('rls_disabled_in_public', { metadata: undefined }));
    assert.match(d.titleJa, /^一部のテーブルで/);
    assert.equal(d.resourceKey, 'advisor:rls_disabled_in_public');
    assert.equal(d.resourceName, undefined);
    assertNoPlaceholders(d);
  });

  it('Storage バケットは bucket:<名前> でまとめる', () => {
    const d = single(lint('public_bucket_allows_listing', { metadata: { schema: 'storage', name: 'avatars', type: 'bucket' } }));
    assert.equal(d.resourceKey, 'bucket:avatars');
    assert.match(d.titleJa, /`avatars`/);
  });

  it('全定義について、リソースあり／なしの両方で文面が完成する', () => {
    for (const name of Object.keys(diagnosticDefinitions)) {
      assertNoPlaceholders(single(lint(name)));
      assertNoPlaceholders(single(lint(name, { metadata: undefined })));
    }
  });
});

describe('不完全な API レスポンス', () => {
  it('lints がなければ null（仕様変更の可能性）', () => {
    assert.equal(diagnoseAdvisorResponse({ results: [] }), null);
    assert.equal(diagnoseAdvisorResponse(null), null);
    assert.equal(diagnoseAdvisorResponse([]), null);
  });

  it('壊れた項目は読み飛ばし、不完全な結果として扱う', () => {
    const r = report(['oops', { title: 'no name' }]);
    assert.equal(r.diagnostics.length, 0);
    assert.deepEqual(r.parseIssues, [
      { index: 0, reason: 'not_an_object' },
      { index: 1, reason: 'missing_name' },
    ]);
    assert.equal(r.incomplete, true);
    assert.equal(r.overall, 'incomplete', '0件でも「大きな指摘なし」にしない');
  });

  it('任意項目（detail / categories / metadata / remediation / cache_key）が欠けても変換できる', () => {
    const d = single({ name: 'rls_disabled_in_public', level: 'ERROR' });
    assert.equal(d.severity, 'danger');
    assert.equal(d.helpUrl, undefined);
    assertNoPlaceholders(d);
  });

  it('https 以外の remediation URL は helpUrl にしない', () => {
    assert.equal(single(lint('rls_disabled_in_public', { remediation: 'javascript:alert(1)' })).helpUrl, undefined);
    assert.equal(single(lint('rls_disabled_in_public', { remediation: 'http://example.com' })).helpUrl, undefined);
  });

  it('SECURITY 以外のカテゴリは除外し、件数を数える', () => {
    const r = report([lint('unindexed_foreign_keys', { categories: ['PERFORMANCE'] }), lint('rls_disabled_in_public')]);
    assert.equal(r.diagnostics.length, 1);
    assert.equal(r.excludedCount, 1);
  });

  it('診断が実行できなかった項目は、カテゴリに関係なく表示し、不完全として扱う', () => {
    const r = report([lint('advisor_check_unavailable', { categories: ['HEALTH'], metadata: { type: 'health' } })]);
    assert.equal(r.diagnostics.length, 1);
    assert.equal(r.diagnostics[0]?.affectsCompleteness, true);
    assert.equal(r.incomplete, true);
    assert.equal(r.overall, 'incomplete');
  });
});

describe('英語の公式説明を含むレスポンス', () => {
  it('日本語の説明には英語をそのまま混ぜず、公式の英語は別フィールドとプロンプトに残す', () => {
    const detail = 'Sample detail: `public.profiles` is reachable from the API and RLS is off.';
    const d = single(lint('rls_disabled_in_public', { detail }));
    assert.equal(d.officialDetail, detail);
    assert.equal(d.officialTitle, 'rls_disabled_in_public');
    assert.ok(!d.explanationJa.includes(detail));
    assert.match(d.explanationJa, /[ぁ-ん]/);
    assert.ok(d.aiFixPrompt.includes(`Supabaseの指摘内容（英語）: ${detail}`));
  });

  it('制御文字や極端に長い公式説明はプロンプト用に整える', () => {
    const d = single(lint('rls_disabled_in_public', { detail: `Line1\u0007\u001b[31m${'x'.repeat(1000)}` }));
    assert.doesNotMatch(d.aiFixPrompt, /[\u0007\u001b]/);
    assert.match(d.aiFixPrompt, /…/);
  });
});

describe('AI修正プロンプト', () => {
  it('SQLを書かせる前に Schema・既存Policy・認証方式・アクセス要件を確認させる', () => {
    const p = single(lint('rls_disabled_in_public')).aiFixPrompt;
    assert.match(p, /`public\.profiles` テーブル/);
    assert.match(p, /## 変更する前に、まず確認してほしいこと/);
    assert.match(p, /現在のSchema/);
    assert.match(p, /既存のRLS Policy/);
    assert.match(p, /認証方式/);
    assert.match(p, /アクセス要件/);
    assert.match(p, /既存機能を壊さないこと/);
    assert.match(p, /推測だけで変更しないこと/);
    assert.match(p, /変更する前に、分かったことと不明な点を私に説明して確認を取ること/);
    assert.match(p, /本番のデータベースへ直接SQLを実行しないこと/);
    assert.match(p, /何を変更したか/);
    assert.match(p, /なぜその変更が必要だったか/);
    assert.match(p, /確認すべきテスト/);
    // 確認の節が、お願いの節より後・守ることの節より前にある
    assert.ok(p.indexOf('まず確認してほしいこと') < p.indexOf('守ってほしいこと'));
  });

  it('全定義・未知項目のプロンプトに共通の確認事項と注意事項が入る', () => {
    for (const name of [...Object.keys(diagnosticDefinitions), 'some_future_lint']) {
      const p = single(lint(name)).aiFixPrompt;
      for (const phrase of ['現在のSchema', '既存のRLS Policy', '認証方式', 'アクセス要件', '既存機能を壊さないこと', '推測だけで変更しないこと']) {
        assert.ok(p.includes(phrase), `${name}: 「${phrase}」がない`);
      }
    }
  });

  it('項目固有の確認・注意事項が追加される', () => {
    const p = single(lint('leaked_service_key', { metadata: undefined })).aiFixPrompt;
    assert.match(p, /キーの値そのものを、出力・ログ・コミットに含めないこと/);
    assert.match(p, /Gitの履歴/);
  });
});

describe('診断定義データ', () => {
  it('全定義が必須項目と分類理由を持つ', () => {
    for (const [name, def] of Object.entries(diagnosticDefinitions)) {
      assert.ok(['danger', 'review', 'info'].includes(def.severity), name);
      assert.ok(def.severityReason.length >= 20, `${name}: 分類理由が短すぎる`);
      assert.ok(def.titleJa && def.explanationJa && def.remediationJa && def.prompt.task, name);
    }
  });

  it('status は公式OpenAPIの掲載状況と一致する', () => {
    for (const [name, def] of Object.entries(diagnosticDefinitions)) {
      assert.equal(def.status, OPENAPI_LINT_NAMES.has(name) ? 'confirmed' : 'unconfirmed', name);
    }
  });

  it('Phase 1 で未確認とした3項目は unconfirmed として定義されている', () => {
    for (const name of ['sensitive_columns_exposed', 'rls_policy_always_true', 'public_bucket_allows_listing']) {
      assert.equal(diagnosticDefinitions[name]?.status, 'unconfirmed', name);
    }
  });
});

describe('レポート全体', () => {
  it('総合結果・件数・並び順・注意書き', () => {
    const r = report(LINTS_WITH_ISSUES.lints);
    assert.equal(r.overall, 'fix-before-release');
    assert.equal(r.headlineJa, '修正してから公開することをおすすめします');
    assert.deepEqual(r.counts, { danger: 2, review: 2, info: 1 });
    const order = r.diagnostics.map((d) => d.severity);
    assert.deepEqual(order, [...order].sort((a, b) => ['danger', 'review', 'info'].indexOf(a) - ['danger', 'review', 'info'].indexOf(b)));
    assert.match(r.disclaimerJa, /Supabase Security Advisor の結果を分かりやすく表示する補助ツールです/);
    assert.match(r.disclaimerJa, /このツールですべてのセキュリティ問題を検出できるわけではありません。/);
  });

  it('指摘0件でも「安全」とは言わない', () => {
    const r = report([]);
    assert.equal(r.overall, 'no-major-findings');
    assert.equal(r.headlineJa, '大きな問題は見つかりませんでした');
    assert.doesNotMatch(r.headlineJa, /安全/);
  });

  it('Legacy トークンの情報を返せる', () => {
    const r = buildDiagnosticReport({ findings: [], issues: [] }, { token: describeToken('sbp_TEST_ONLY_LEGACY') });
    assert.equal(r.token?.kind, 'classic');
    assert.equal(r.token?.isBroadAccess, true);
    assert.match(r.token?.noticeJa ?? '', /Advisors: Read/);
    assert.equal(describeToken('sbp_fc123').isBroadAccess, false);
  });

  it('同梱サンプルを変換できる', () => {
    const path = fileURLToPath(new URL('../../samples/security-advisors.sample.json', import.meta.url));
    const r = diagnoseAdvisorResponse(JSON.parse(readFileSync(path, 'utf8')));
    assert.ok(r);
    assert.equal(r.diagnostics.length, 6);
    assert.deepEqual(r.unknownAdvisorNames, ['some_future_lint']);
  });

  it('toDiagnostic は正規化済みの1件から直接変換できる', () => {
    const result = normalizeSecurityAdvisors({ lints: [lint('rls_disabled_in_public')] });
    const finding = result?.findings[0] as AdvisorFinding;
    assert.equal(toDiagnostic(finding).severity, 'danger');
  });
});

describe('プライバシー: 診断変換はローカルのみ', () => {
  it('diagnostics/ と explanations/ に通信処理がない', () => {
    const srcRoot = fileURLToPath(new URL('../../src', import.meta.url));
    for (const dir of ['diagnostics', 'explanations', 'types']) {
      for (const file of readdirSync(join(srcRoot, dir))) {
        const code = readFileSync(join(srcRoot, dir, file), 'utf8');
        assert.doesNotMatch(code, /\bfetch\s*\(|node:https?|node:net|XMLHttpRequest|WebSocket/, `${dir}/${file}`);
        assert.doesNotMatch(code, /openai|anthropic/i, `${dir}/${file}`);
      }
    }
  });
});
