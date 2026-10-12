// Security Advisor API の応答（ApiLint 形式）を、API非依存の AdvisorFinding へ変換する。
// API 仕様が変わった場合はこのファイルと validate.ts / types.ts だけを直す。
//
// 方針: 1件が壊れていても全体を失敗にしない。読めない項目は issues に記録し、
// 「診断結果が不完全な可能性」として後段に伝える（0件＝安全と誤解させないため）。

import { toSafeHelpUrl } from '../shared/url.js';
import type { AdvisorFinding, AdvisorParseIssue, AdvisorResource, OfficialSeverity, SecurityAdvisorResult } from '../types/advisor.js';

const OFFICIAL_LEVELS: ReadonlySet<string> = new Set(['ERROR', 'WARN', 'INFO']);

/**
 * 1回の診断で扱う指摘の上限。通常のプロジェクトでは数十件程度のため、十分に余裕を持たせた値。
 * 極端な応答でレポートが巨大化（数百MB〜GB）するのを防ぐ。超えた分は issues に記録し、不完全として扱う。
 */
export const MAX_FINDINGS = 2000;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function toResource(metadata: Record<string, unknown>): AdvisorResource | undefined {
  const resource: AdvisorResource = {
    type: str(metadata.type),
    schema: str(metadata.schema),
    // bucket 系は bucket_name を持つことがある
    name: str(metadata.name) ?? str(metadata.bucket_name) ?? str(metadata.entity),
  };
  return resource.type || resource.schema || resource.name ? resource : undefined;
}

/**
 * Security Advisor の応答本文を正規化する。
 * `lints` 配列自体がない場合は null（API仕様変更の可能性）を返す。
 */
export function normalizeSecurityAdvisors(body: unknown): SecurityAdvisorResult | null {
  if (!isObject(body) || !Array.isArray(body.lints)) return null;

  const findings: AdvisorFinding[] = [];
  const issues: AdvisorParseIssue[] = [];

  body.lints.forEach((item: unknown, index: number) => {
    if (index >= MAX_FINDINGS) {
      if (index === MAX_FINDINGS) issues.push({ index, reason: 'too_many' });
      return;
    }
    if (!isObject(item)) {
      issues.push({ index, reason: 'not_an_object' });
      return;
    }
    const advisorName = str(item.name);
    if (!advisorName) {
      issues.push({ index, reason: 'missing_name' });
      return;
    }

    const rawLevel = str(item.level);
    let officialSeverity: OfficialSeverity | undefined;
    if (rawLevel && OFFICIAL_LEVELS.has(rawLevel)) {
      officialSeverity = rawLevel as OfficialSeverity;
    } else {
      issues.push({ index, reason: 'unknown_level' });
    }

    const metadata = isObject(item.metadata) ? { ...item.metadata } : {};

    findings.push({
      advisorName,
      title: str(item.title) ?? advisorName,
      officialSeverity,
      rawLevel,
      categories: Array.isArray(item.categories) ? item.categories.filter((c): c is string => typeof c === 'string') : [],
      description: str(item.description) ?? '',
      detail: str(item.detail) ?? '',
      helpUrl: toSafeHelpUrl(item.remediation),
      resource: toResource(metadata),
      metadata,
      cacheKey: str(item.cache_key),
      observedAt: str(item.observed_at),
      raw: item,
    });
  });

  return { findings, issues };
}
