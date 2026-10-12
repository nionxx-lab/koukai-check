import type { AdvisorFinding } from '../types/advisor.js';

const RELATION_TYPES = new Set(['table', 'view', 'materialized view', 'foreign table']);

/**
 * 同じ対象への指摘をまとめるためのキーを作る。
 * テーブル・ビュー等は種類を問わず relation:<schema>.<name> にそろえる
 * （同じテーブルへの rls_disabled_in_public と sensitive_columns_exposed を同じグループにするため）。
 */
export function resourceKeyOf(finding: AdvisorFinding): string {
  const r = finding.resource;
  const qualified = r?.name ? (r.schema ? `${r.schema}.${r.name}` : r.name) : undefined;

  if (r?.type && RELATION_TYPES.has(r.type) && qualified) return `relation:${qualified}`;
  if (r?.type === 'bucket' && r.name) return `bucket:${r.name}`;
  if (r?.type === 'auth') return 'project:auth';
  if (r?.type && qualified) return `${r.type}:${qualified}`;
  if (qualified) return `resource:${qualified}`;
  // 対象を持たない指摘（プロジェクト設定など）は Advisor 名ごとにまとめる
  return `advisor:${finding.advisorName}`;
}
