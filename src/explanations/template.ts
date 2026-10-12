// 診断定義の文面に含まれる {placeholder} を埋める。外部APIは使わず、すべてローカルで生成する。

export interface TemplateContext {
  /** 例: 「`public.profiles` テーブル」。対象が不明な場合は定義側の fallbackTarget */
  target: string;
  /** 例: 「profiles」。不明な場合は fallbackTarget */
  name: string;
  /** 例: 「（該当しそうな列: email, phone）」。情報がなければ空文字 */
  sensitiveColumns: string;
}

const PLACEHOLDER = /\{(target|name|sensitiveColumns)\}/g;

export function fillTemplate(template: string, ctx: TemplateContext): string {
  return template.replace(PLACEHOLDER, (_match, key: keyof TemplateContext) => ctx[key]);
}

const RESOURCE_TYPE_LABELS: Record<string, string> = {
  table: 'テーブル',
  view: 'ビュー',
  'materialized view': 'マテリアライズドビュー',
  'foreign table': '外部テーブル',
  function: '関数',
  extension: '拡張機能',
  bucket: 'Storageバケット',
};

export function resourceTypeLabel(type: string | undefined): string | undefined {
  return type ? RESOURCE_TYPE_LABELS[type] : undefined;
}

/**
 * 公式の英語 detail をプロンプトへ埋め込む前に整える。
 * テーブル名などはユーザー自身が付けたものだが、制御文字や極端に長い文字列は除く。
 */
export function sanitizeForPrompt(text: string, maxLength = 500): string {
  // eslint-disable-next-line no-control-regex
  const cleaned = text
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ') // 改行も含めて1行にする（指示行の紛れ込み防止）
    .replace(/[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  return cleaned.length > maxLength ? `${cleaned.slice(0, maxLength)}…` : cleaned;
}
