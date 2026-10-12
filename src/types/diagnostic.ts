import type { AdvisorParseIssue, OfficialSeverity } from './advisor.js';

export type DiagnosticSeverity = 'danger' | 'review' | 'info';

export type ShouldFixBeforeRelease = 'yes' | 'review' | 'no';

/**
 * 診断定義の確認状況。
 * - confirmed:   Supabase 公式 OpenAPI の lint 一覧に載っている
 * - unconfirmed: Advisor の診断SQL（splinter）にはあるが OpenAPI 一覧に未掲載。API が実際に返すかは未確認
 * - unknown:     このツールに定義がない（新しい診断項目など）
 */
export type DefinitionStatus = 'confirmed' | 'unconfirmed' | 'unknown';

export interface Diagnostic {
  id: string;
  advisorName: string;

  severity: DiagnosticSeverity;
  /** この分類にした理由（公式Severityと異なる場合は特に重要） */
  severityReason: string;

  titleJa: string;
  explanationJa: string;
  shouldFixBeforeRelease: ShouldFixBeforeRelease;
  remediationJa: string;
  aiFixPrompt: string;

  resourceType?: string;
  resourceSchema?: string;
  resourceName?: string;
  /** 同じ対象（テーブル等）への指摘をまとめるためのキー。例: relation:public.profiles */
  resourceKey: string;

  observedAt?: string;
  officialSeverity?: OfficialSeverity;
  officialTitle: string;
  officialDetail: string;
  helpUrl?: string;

  definitionStatus: DefinitionStatus;
  /** true の場合、この指摘は「診断自体が一部実行できなかった」ことを表す */
  affectsCompleteness: boolean;

  /** 詳細表示用。通常画面には出さない */
  originalAdvisorData: unknown;
}

export interface ResourceGroup {
  resourceKey: string;
  resourceType?: string;
  resourceSchema?: string;
  resourceName?: string;
  /** グループ内で最も重い分類 */
  severity: DiagnosticSeverity;
  diagnosticIds: string[];
}

export type OverallStatus =
  | 'fix-before-release' // 危険が1件以上
  | 'review-before-release' // 要確認が1件以上
  | 'incomplete' // 指摘はないが、診断が不完全な可能性がある
  | 'no-major-findings'; // 大きな指摘なし（「安全」とは言わない）

export type TokenKind = 'scoped' | 'classic' | 'unknown';

export interface TokenInfo {
  kind: TokenKind;
  /** アカウントの全権限を持つトークンか */
  isBroadAccess: boolean;
  noticeJa?: string;
}

export interface DiagnosticReport {
  overall: OverallStatus;
  headlineJa: string;
  counts: Record<DiagnosticSeverity, number>;
  /** 重い順（danger → review → info）に並べた診断 */
  diagnostics: Diagnostic[];
  /** 同一リソースのまとめ（Phase 3 の表示用） */
  groups: ResourceGroup[];
  observedAt: { earliest?: string; latest?: string };
  /** このツールに定義がなかった Advisor 名（API変更の検知用） */
  unknownAdvisorNames: string[];
  parseIssues: AdvisorParseIssue[];
  /** SECURITY 以外のカテゴリとして除外した件数 */
  excludedCount: number;
  /** 解析できない項目や、診断が実行できなかった項目がある */
  incomplete: boolean;
  token?: TokenInfo;
  disclaimerJa: string;
}
