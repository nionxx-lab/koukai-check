// Supabase API から独立した、正規化済みの Advisor 指摘。
// supabase/normalize.ts だけがこの型を生成し、diagnostics/ 以降はこの型だけを扱う。

export type OfficialSeverity = 'ERROR' | 'WARN' | 'INFO';

export interface AdvisorResource {
  /** table / view / materialized view / foreign table / function / extension / bucket / auth など */
  type?: string;
  schema?: string;
  name?: string;
}

export interface AdvisorFinding {
  advisorName: string;
  /** 公式タイトル（英語） */
  title: string;
  /** 既知の値（ERROR / WARN / INFO）の場合のみ設定 */
  officialSeverity?: OfficialSeverity;
  /** API が返した level をそのまま保持（未知の値の検知用） */
  rawLevel?: string;
  categories: string[];
  /** lint 全体の公式説明（英語） */
  description: string;
  /** 個別の指摘（英語・対象名入り） */
  detail: string;
  /** 公式ドキュメントのURL（https のみ） */
  helpUrl?: string;
  resource?: AdvisorResource;
  /** lint ごとに異なる追加情報（sensitive_columns, policy_name など） */
  metadata: Record<string, unknown>;
  cacheKey?: string;
  observedAt?: string;
  /** API から受け取った元データ（詳細表示用） */
  raw: unknown;
}

export interface AdvisorParseIssue {
  /** lints 配列内の位置 */
  index: number;
  /** too_many: 件数が上限を超えたため、それ以降を読み飛ばした */
  reason: 'not_an_object' | 'missing_name' | 'unknown_level' | 'too_many';
}

export interface SecurityAdvisorResult {
  findings: AdvisorFinding[];
  /** 読み飛ばした・不完全だった項目。1件でもあれば「診断結果が不完全な可能性」として扱う */
  issues: AdvisorParseIssue[];
}
