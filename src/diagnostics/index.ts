// Supabase Advisor Response → normalize → classify → 日本語 Diagnostic[] の入口。
// ネットワーク通信は行わない（取得は supabase/client.ts の役割）。

import { normalizeSecurityAdvisors } from '../supabase/normalize.js';
import type { DiagnosticReport } from '../types/diagnostic.js';
import { buildDiagnosticReport, type BuildReportOptions } from './classify.js';

export { buildDiagnosticReport, toDiagnostic, DISCLAIMER_JA } from './classify.js';

/**
 * Security Advisor API の応答本文（JSON）から診断レポートを作る。
 * 応答の形が想定外（`lints` がない等）の場合は null を返す。
 */
export function diagnoseAdvisorResponse(body: unknown, options: BuildReportOptions = {}): DiagnosticReport | null {
  const result = normalizeSecurityAdvisors(body);
  return result ? buildDiagnosticReport(result, options) : null;
}
