// 実行時の形チェック。依存を増やさないため zod 等は使わない。
// Security Advisor の応答は normalize.ts で項目単位に検査する。

import type { ApiProject } from './types.js';

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isString(value: unknown): value is string {
  return typeof value === 'string';
}

export function parseProjects(body: unknown): ApiProject[] | null {
  if (!Array.isArray(body)) return null;
  const projects: ApiProject[] = [];
  for (const item of body) {
    if (!isObject(item) || !isString(item.ref) || !isString(item.name)) return null;
    projects.push({
      id: isString(item.id) ? item.id : item.ref,
      ref: item.ref,
      name: item.name,
      organization_id: isString(item.organization_id) ? item.organization_id : undefined,
      organization_slug: isString(item.organization_slug) ? item.organization_slug : undefined,
      region: isString(item.region) ? item.region : undefined,
      created_at: isString(item.created_at) ? item.created_at : undefined,
      status: isString(item.status) ? item.status : undefined,
    });
  }
  return projects;
}
