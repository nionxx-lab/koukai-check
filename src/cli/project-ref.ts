import { isValidProjectRef } from '../supabase/client.js';
import { isSupabaseHost } from '../shared/url.js';

/**
 * ユーザー入力からプロジェクトIDを取り出す。
 * 受け付ける形式:
 *   ・プロジェクトIDそのもの（英小文字20文字）
 *   ・ダッシュボードのURL（https://supabase.com/dashboard/project/<ref>/...）
 *   ・プロジェクトのAPI URL（https://<ref>.supabase.co）
 * 取り出すのはIDだけで、入力されたURLのホストへ通信することはない（通信先は api.supabase.com 固定）。
 * 紛らわしい入力を避けるため、Supabase以外のドメインのURLは受け付けない。
 */
export function extractProjectRef(input: string): string | null {
  const trimmed = input.replace(/[\u200b-\u200d\u2060\ufeff]/g, '').trim();
  if (trimmed.length > 2048) return null;
  if (isValidProjectRef(trimmed)) return trimmed;

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  if (url.username || url.password) return null;
  const host = url.hostname.toLowerCase();

  if (isSupabaseHost(host)) {
    const m = url.pathname.match(/\/project\/([a-z]{20})(?:\/|$)/);
    return m?.[1] ?? null;
  }
  const api = host.match(/^([a-z]{20})\.supabase\.co$/);
  return api?.[1] ?? null;
}
