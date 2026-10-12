import { toSafeHelpUrl } from '../shared/url.js';

// HTMLへ埋め込む文字列はすべてこの関数を通す。
// テーブル名・スキーマ名・Advisorの文字列など、ユーザーのプロジェクト由来の値が含まれるため。

const ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
  '`': '&#96;',
};

export function escapeHtml(value: unknown): string {
  return String(value ?? '').replace(/[&<>"'`]/g, (ch) => ESCAPES[ch] ?? ch);
}

/** href に使う URL。toSafeHelpUrl を通ったものだけをエスケープして返す。 */
export function safeHref(url: string | undefined): string | undefined {
  const safe = toSafeHelpUrl(url);
  return safe ? escapeHtml(safe) : undefined;
}

/**
 * `...` で囲まれた部分を <code> にして表示する。各部分は必ず escapeHtml してから組み立てる。
 * 診断定義の文面は対象名を `public.profiles` のように書いているため。
 */
export function escapeWithInlineCode(value: string): string {
  const parts = value.split('`');
  // バッククォートが閉じていない場合は、そのままエスケープして表示する
  if (parts.length % 2 === 0) return escapeHtml(value);
  return parts.map((part, i) => (i % 2 === 1 ? `<code>${escapeHtml(part)}</code>` : escapeHtml(part))).join('');
}
