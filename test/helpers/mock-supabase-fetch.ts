// E2E テスト用: CLI の子プロセスに --import で読み込み、api.supabase.com への fetch だけを差し替える。
// 製品コードには、通信先を変える仕組みを一切入れていない（テスト専用の差し替え）。
//
// KC_TEST_FIXTURE: 返す Security Advisor 応答の JSON ファイル
// KC_TEST_STATUS:  返す HTTP ステータス（省略時 200）
// KC_TEST_NETWORK_ERROR: 1 なら接続エラーにする

import { readFileSync } from 'node:fs';

const fixture = process.env.KC_TEST_FIXTURE;
const status = Number(process.env.KC_TEST_STATUS ?? '200');
const networkError = process.env.KC_TEST_NETWORK_ERROR === '1';

const guarded = globalThis.fetch;
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
  if (url.origin !== 'https://api.supabase.com') return guarded(input, init);

  const auth = new Headers(init?.headers).get('authorization') ?? '';
  // 受け取ったトークンを、値ではなく長さと末尾だけ記録する（テストで「本当に送られたか」を確かめるため）
  process.stderr.write(`MOCK_REQUEST ${url.pathname} auth_len=${auth.length} auth_tail_ok=${auth.endsWith('_123456')}\n`);
  if (networkError) throw new TypeError('fetch failed');
  if (status !== 200) {
    return new Response(JSON.stringify({ message: 'mock error' }), { status, headers: { 'content-type': 'application/json' } });
  }
  return new Response(readFileSync(fixture ?? '', 'utf8'), { status: 200, headers: { 'content-type': 'application/json' } });
}) as typeof fetch;
