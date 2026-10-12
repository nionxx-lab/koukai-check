// URL の安全確認（共通）。リンク化してよいか、プロジェクトURLとして受け付けてよいかを判定する。

/**
 * 公式の解説リンクとして表示してよい URL か。
 * https のみ、かつ Supabase のドメイン（supabase.com とそのサブドメイン）だけを許可する。
 * javascript: / data: / file: / http: / 認証情報付き URL などは拒否する。
 * 不可の場合は undefined を返す（リンクにはせず、元データとして文字で表示するだけ）。
 */
export function toSafeHelpUrl(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2048) return undefined;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return undefined;
  }
  if (url.protocol !== 'https:') return undefined;
  if (url.username || url.password) return undefined;
  if (url.port && url.port !== '443') return undefined;
  if (!isSupabaseHost(url.hostname)) return undefined;
  return url.toString();
}

export function isSupabaseHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  return host === 'supabase.com' || host.endsWith('.supabase.com');
}

/** アプリ画面からリンクしてよい公式ドキュメントのホスト（チェック定義に書いたものだけ） */
export const APP_DOC_HOSTS: ReadonlySet<string> = new Set(['supabase.com', 'firebase.google.com', 'docs.expo.dev', 'nextjs.org']);

/**
 * 専用ウィンドウの中のリンクを、既定のブラウザで開いてよいか。
 * 画面に出しているリンク（Supabase の解説・トークンのページ、各技術の公式ドキュメント）と同じ範囲だけを許可する。
 * それ以外（http・ファイル・ほかのサイト・認証情報やポート付きの URL）は開かない。
 */
export function isAllowedExternalUrl(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 2048 || /[\s"<>\\^`{|}\u0000-\u001f\u007f]/.test(value)) return false;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443')) return false;
  return isSupabaseHost(url.hostname) || APP_DOC_HOSTS.has(url.hostname.toLowerCase());
}
