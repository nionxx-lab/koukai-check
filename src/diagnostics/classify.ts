// 正規化済みの Advisor 指摘 → 初心者向け診断（Diagnostic）への変換。
// 分類は definitions.ts の対応表で決め、公式 level は使わない（未知の項目を除く）。

import { getDefinition, type DiagnosticDefinition, type PromptSpec } from '../explanations/definitions.js';
import { buildAiFixPrompt } from '../explanations/prompt.js';
import { fillTemplate, resourceTypeLabel, type TemplateContext } from '../explanations/template.js';
import type { AdvisorFinding, SecurityAdvisorResult } from '../types/advisor.js';
import type {
  Diagnostic,
  DiagnosticReport,
  DiagnosticSeverity,
  OverallStatus,
  ResourceGroup,
  ShouldFixBeforeRelease,
  TokenInfo,
} from '../types/diagnostic.js';
import { resourceKeyOf } from './resource.js';

export const DISCLAIMER_JA =
  'このツールは Supabase Security Advisor の結果を分かりやすく表示する補助ツールです。' +
  'このツールですべてのセキュリティ問題を検出できるわけではありません。問題が表示されないことは、安全の保証ではありません。';

const SEVERITY_ORDER: Record<DiagnosticSeverity, number> = { danger: 0, review: 1, info: 2 };

const DEFAULT_SHOULD_FIX: Record<DiagnosticSeverity, ShouldFixBeforeRelease> = {
  danger: 'yes',
  review: 'review',
  info: 'no',
};

// ───────────── 未知の Advisor 用の汎用定義 ─────────────

const UNKNOWN_PROMPT: PromptSpec = {
  task:
    'この指摘の意味を公式の解説で確認し、このアプリにとって問題かどうかを判断してください。' +
    '問題がある場合は修正方針を提案し、私の確認を取ってから修正してください。',
};

function unknownDefinition(finding: AdvisorFinding): Omit<DiagnosticDefinition, 'status'> {
  return {
    // 未知の項目は重さを判断できないため「参考」とする。ただし「安全」とは扱わない。
    severity: 'info',
    severityReason:
      `このツールに定義がない、新しい診断項目です（公式の重要度: ${finding.officialSeverity ?? sanitizeName(finding.rawLevel ?? '不明')}）。` +
      '内容を判断できないため「参考」として表示しますが、問題がないという意味ではありません。',
    shouldFixBeforeRelease: 'review',
    fallbackTarget: 'このプロジェクト',
    titleJa: `Supabaseから新しい診断項目が返されました（${sanitizeName(finding.advisorName)}）`,
    explanationJa:
      'このツールがまだ対応していない診断項目です。内容を日本語で説明できないため、下の公式の説明（英語）と解説ページを確認してください。' +
      'このツールが対応していないだけで、問題がないという意味ではありません。',
    remediationJa: '公式の解説ページで内容を確認し、このアプリにとって問題かどうかを判断してください。判断が難しい場合は、下の指示文をAIに渡して相談できます。',
    prompt: UNKNOWN_PROMPT,
  };
}

// ───────────── 変換 ─────────────

/** 表示用の名前の最大長。極端に長いテーブル名などでレポートが崩れないようにする。 */
export const MAX_NAME_LENGTH = 200;

/**
 * テーブル名・スキーマ名など、プロジェクト由来の名前を文面へ入れる前に整える。
 * Postgres では引用符付きの識別子に改行や記号を含められるため、
 * AI修正指示に余計な指示行を紛れ込ませたり（プロンプトインジェクション）、
 * 文字の向きを逆転させる制御文字で見た目をごまかしたりできないようにする。
 */
export function sanitizeName(value: string): string {
  const cleaned = value
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ') // 改行・制御文字
    .replace(/[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g, '') // ゼロ幅・双方向制御文字
    .replace(/`/g, "'") // 文面中のコード表記（`...`）を壊さない
    .replace(/\s+/g, ' ')
    .trim();
  return cleaned.length > MAX_NAME_LENGTH ? `${cleaned.slice(0, MAX_NAME_LENGTH)}…` : cleaned;
}

function templateContext(finding: AdvisorFinding, fallbackTarget: string): TemplateContext {
  const r = finding.resource;
  const schema = r?.schema ? sanitizeName(r.schema) : undefined;
  const name = r?.name ? sanitizeName(r.name) : undefined;
  const qualified = name ? (schema ? `${schema}.${name}` : name) : undefined;
  const label = resourceTypeLabel(r?.type);

  const columns = Array.isArray(finding.metadata.sensitive_columns)
    ? finding.metadata.sensitive_columns.filter((c): c is string => typeof c === 'string').slice(0, 20).map(sanitizeName)
    : [];

  return {
    target: qualified ? `\`${qualified}\`${label ? ` ${label}` : ''}` : fallbackTarget,
    name: name ? `\`${name}\`` : fallbackTarget,
    sensitiveColumns: columns.length > 0 ? `（該当しそうな列: ${columns.join(', ')}）` : '',
  };
}

export function toDiagnostic(finding: AdvisorFinding): Diagnostic {
  const known = getDefinition(finding.advisorName);
  const def = known ?? unknownDefinition(finding);
  const ctx = templateContext(finding, def.fallbackTarget);
  const fill = (text: string) => fillTemplate(text, ctx);
  const resourceKey = resourceKeyOf(finding);

  return {
    id: `${finding.advisorName}:${finding.cacheKey ?? resourceKey}`,
    advisorName: finding.advisorName,
    severity: def.severity,
    severityReason: def.severityReason,
    titleJa: fill(def.titleJa),
    explanationJa: fill(def.explanationJa),
    shouldFixBeforeRelease: def.shouldFixBeforeRelease ?? DEFAULT_SHOULD_FIX[def.severity],
    remediationJa: fill(def.remediationJa),
    aiFixPrompt: buildAiFixPrompt({
      advisorName: finding.advisorName,
      spec: def.prompt,
      ctx,
      officialDetail: finding.detail || finding.description || finding.title,
      helpUrl: finding.helpUrl,
    }),
    resourceType: finding.resource?.type,
    resourceSchema: finding.resource?.schema,
    resourceName: finding.resource?.name,
    resourceKey,
    observedAt: finding.observedAt,
    officialSeverity: finding.officialSeverity,
    officialTitle: finding.title,
    officialDetail: finding.detail || finding.description,
    helpUrl: finding.helpUrl,
    definitionStatus: known ? known.status : 'unknown',
    affectsCompleteness: def.affectsCompleteness ?? false,
    originalAdvisorData: finding.raw,
  };
}

/** Security Advisor の結果のうち、このツールで扱う指摘か。 */
function isInScope(finding: AdvisorFinding): boolean {
  const def = getDefinition(finding.advisorName);
  if (def?.alwaysInclude) return true;
  // カテゴリ情報がない場合は、Security Advisor の結果なので対象に含める
  if (finding.categories.length === 0) return true;
  return finding.categories.includes('SECURITY');
}

function makeIdsUnique(diagnostics: Diagnostic[]): void {
  const seen = new Map<string, number>();
  for (const d of diagnostics) {
    const count = seen.get(d.id) ?? 0;
    seen.set(d.id, count + 1);
    if (count > 0) d.id = `${d.id}#${count + 1}`;
  }
}

function groupByResource(diagnostics: Diagnostic[]): ResourceGroup[] {
  const groups = new Map<string, ResourceGroup>();
  for (const d of diagnostics) {
    const group = groups.get(d.resourceKey);
    if (group) {
      group.diagnosticIds.push(d.id);
      if (SEVERITY_ORDER[d.severity] < SEVERITY_ORDER[group.severity]) group.severity = d.severity;
    } else {
      groups.set(d.resourceKey, {
        resourceKey: d.resourceKey,
        resourceType: d.resourceType,
        resourceSchema: d.resourceSchema,
        resourceName: d.resourceName,
        severity: d.severity,
        diagnosticIds: [d.id],
      });
    }
  }
  return [...groups.values()].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}

const HEADLINES: Record<OverallStatus, string> = {
  'fix-before-release': '修正してから公開することをおすすめします',
  'review-before-release': 'いくつか確認してから公開することをおすすめします',
  // 「安全」とは言わない。不完全な場合は画面上部の注意書きとあわせて表示する
  incomplete: '大きな問題は見つかりませんでしたが、確認できなかった項目があります',
  'no-major-findings': '大きな問題は見つかりませんでした',
};

export interface BuildReportOptions {
  token?: TokenInfo;
}

export function buildDiagnosticReport(result: SecurityAdvisorResult, options: BuildReportOptions = {}): DiagnosticReport {
  const inScope = result.findings.filter(isInScope);
  const diagnostics = inScope.map(toDiagnostic);

  // 重い順 → 同じ対象 → Advisor 名の順に並べる（同じテーブルへの指摘が近くに並ぶ）
  diagnostics.sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      a.resourceKey.localeCompare(b.resourceKey) ||
      a.advisorName.localeCompare(b.advisorName),
  );
  makeIdsUnique(diagnostics);

  const counts: Record<DiagnosticSeverity, number> = { danger: 0, review: 0, info: 0 };
  for (const d of diagnostics) counts[d.severity]++;

  const observed = diagnostics.map((d) => d.observedAt).filter((v): v is string => Boolean(v)).sort();
  const unknownAdvisorNames = [...new Set(diagnostics.filter((d) => d.definitionStatus === 'unknown').map((d) => d.advisorName))];
  const incomplete = result.issues.length > 0 || diagnostics.some((d) => d.affectsCompleteness);

  let overall: OverallStatus;
  if (counts.danger > 0) overall = 'fix-before-release';
  else if (counts.review > 0 || unknownAdvisorNames.length > 0) overall = 'review-before-release';
  else if (incomplete) overall = 'incomplete';
  else overall = 'no-major-findings';

  return {
    overall,
    headlineJa: HEADLINES[overall],
    counts,
    diagnostics,
    groups: groupByResource(diagnostics),
    observedAt: { earliest: observed[0], latest: observed[observed.length - 1] },
    unknownAdvisorNames,
    parseIssues: result.issues,
    excludedCount: result.findings.length - inScope.length,
    incomplete,
    token: options.token,
    disclaimerJa: DISCLAIMER_JA,
  };
}
