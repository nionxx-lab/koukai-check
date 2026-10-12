// Supabase Management API への依存はこのディレクトリに閉じ込める。
// API仕様が変わった場合は supabase/ だけを直せば済むようにする。
//
// 通信先は api.supabase.com のみ。環境変数等で接続先を変えられるようにはしない
// （トークンを第三者のサーバーへ送らせる経路を作らないため）。

import { SupabaseApiError, kindFromStatus } from './errors.js';
import type { SecurityAdvisorResult } from '../types/advisor.js';
import { normalizeSecurityAdvisors } from './normalize.js';
import type { ApiProject } from './types.js';
import { parseProjects } from './validate.js';

export const SUPABASE_API_ORIGIN = 'https://api.supabase.com';

const REQUEST_TIMEOUT_MS = 20_000;

/** 応答本文の上限。通常の Security Advisor の応答は数KB〜数百KB。極端な応答でメモリを使い切らないようにする。 */
export const MAX_RESPONSE_BYTES = 20 * 1024 * 1024;

export interface ManagementClientOptions {
  token: string;
  /** テスト専用。本番コードからは指定しない。 */
  baseUrl?: string;
  /** テスト専用。 */
  fetchImpl?: typeof fetch;
  /** テスト専用。 */
  timeoutMs?: number;
  /** テスト専用。応答の大きさの上限（既定は MAX_RESPONSE_BYTES） */
  maxResponseBytes?: number;
}

export interface ManagementClient {
  /** MVPの標準フローでは使わない（Projects (account-wide): Read が必要なため）。--list-projects 指定時のみ。 */
  listProjects(): Promise<ApiProject[]>;
  /** 必要な権限は対象プロジェクトの Advisors: Read のみ。 */
  getSecurityAdvisors(projectRef: string): Promise<SecurityAdvisorResult>;
}

const PROJECT_REF_PATTERN = /^[a-z]{20}$/;

export function isValidProjectRef(ref: string): boolean {
  return PROJECT_REF_PATTERN.test(ref);
}

export function createManagementClient(options: ManagementClientOptions): ManagementClient {
  const baseUrl = options.baseUrl ?? SUPABASE_API_ORIGIN;
  const fetchImpl = options.fetchImpl ?? fetch;

  const expectedOrigin = new URL(baseUrl).origin;

  async function getJson(path: string): Promise<unknown> {
    const url = new URL(path, baseUrl);
    // 多重防御: どんな path が渡されても、通信先が固定のオリジン以外になることはない
    if (url.origin !== expectedOrigin || !path.startsWith('/v1/')) {
      throw new SupabaseApiError('unexpected_response', path, '想定外の通信先です');
    }
    const signal = AbortSignal.timeout(options.timeoutMs ?? REQUEST_TIMEOUT_MS);
    let response: Response;
    try {
      response = await fetchImpl(url, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${options.token}`,
          Accept: 'application/json',
        },
        // リダイレクトは追わない（通信先を api.supabase.com から変えない・トークンを別ホストへ送らない）
        redirect: 'error',
        signal,
      });
    } catch (cause) {
      throw new SupabaseApiError('network', path, `Supabaseに接続できませんでした: ${describeCause(cause)}`);
    }

    if (!response.ok) {
      // Supabase API のエラーは JSON で返る。JSON以外の 401/403 はプロキシ等の中継機器の拒否とみなし、
      // 「トークンの権限不足」と誤案内しない。
      const isJson = response.headers.get('content-type')?.includes('application/json') ?? false;
      if ((response.status === 401 || response.status === 403) && !isJson) {
        throw new SupabaseApiError('network', path, `プロキシ等により接続が拒否されました (HTTP ${response.status})`, response.status);
      }
      // レスポンス本文はユーザーにそのまま出さない（内容が不定のため）。
      throw new SupabaseApiError(kindFromStatus(response.status), path, `HTTP ${response.status}`, response.status);
    }

    let text: string;
    try {
      text = await readLimitedText(response, options.maxResponseBytes ?? MAX_RESPONSE_BYTES);
    } catch (cause) {
      if (cause instanceof SupabaseApiError) throw cause;
      throw new SupabaseApiError('network', path, `応答の受信中に接続が切れました: ${describeCause(cause)}`, response.status);
    }
    try {
      return JSON.parse(text);
    } catch {
      throw new SupabaseApiError('unexpected_response', path, 'JSONとして読み取れない応答でした', response.status);
    }
  }

  async function readLimitedText(response: Response, maxBytes: number): Promise<string> {
    const declared = Number(response.headers.get('content-length') ?? '0');
    if (declared > maxBytes) throw new SupabaseApiError('unexpected_response', '', '応答が大きすぎます', response.status);
    if (!response.body) return '';
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new SupabaseApiError('unexpected_response', '', '応答が大きすぎます', response.status);
      }
      chunks.push(value);
    }
    return new TextDecoder('utf-8').decode(Buffer.concat(chunks));
  }

  return {
    async listProjects() {
      const path = '/v1/projects';
      const projects = parseProjects(await getJson(path));
      if (!projects) {
        throw new SupabaseApiError('unexpected_response', path, 'プロジェクト一覧の形式が想定と異なります');
      }
      return projects;
    },

    async getSecurityAdvisors(projectRef: string) {
      if (!isValidProjectRef(projectRef)) {
        throw new SupabaseApiError('not_found', '/v1/projects/{ref}/advisors/security', 'プロジェクトIDの形式が正しくありません');
      }
      const path = `/v1/projects/${projectRef}/advisors/security`;
      const result = normalizeSecurityAdvisors(await getJson(path));
      if (!result) {
        throw new SupabaseApiError('unexpected_response', path, 'Security Advisorの結果の形式が想定と異なります');
      }
      return result;
    },
  };
}

function describeCause(cause: unknown): string {
  if (cause instanceof Error) {
    if (cause.name === 'TimeoutError') return 'タイムアウトしました';
    return cause.message;
  }
  return String(cause);
}
