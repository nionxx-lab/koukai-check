import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, beforeEach, describe, it } from 'node:test';
import { explainError } from '../src/cli/messages.js';
import { extractProjectRef } from '../src/cli/project-ref.js';
import { createManagementClient, SUPABASE_API_ORIGIN } from '../src/supabase/client.js';
import { SupabaseApiError } from '../src/supabase/errors.js';
import { detectTokenKind } from '../src/supabase/token.js';
import { LINTS_WITH_ISSUES, PROJECT_A, PROJECT_B } from './fixtures.js';

type Handler = (req: IncomingMessage, res: ServerResponse) => void;

const VALID_TOKEN = 'sbp_fc_test_token';
let server: Server;
let baseUrl: string;
let handler: Handler;
let requests: { url: string; auth: string | undefined }[] = [];

function json(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

before(async () => {
  server = createServer((req, res) => {
    requests.push({ url: req.url ?? '', auth: req.headers.authorization });
    handler(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => server.close());

beforeEach(() => {
  requests = [];
});

/** 公式OpenAPIの挙動を模したモック。 */
function mockSupabase(options: {
  projects?: unknown[];
  lints?: unknown;
  projectsStatus?: number;
  advisorsStatus?: number;
}): Handler {
  return (req, res) => {
    if (req.headers.authorization !== `Bearer ${VALID_TOKEN}`) return json(res, 401, { message: 'Unauthorized' });
    if (req.url === '/v1/projects') {
      if (options.projectsStatus) return json(res, options.projectsStatus, { message: 'error' });
      return json(res, 200, options.projects ?? [PROJECT_A]);
    }
    const m = req.url?.match(/^\/v1\/projects\/([a-z]{20})\/advisors\/security$/);
    if (m) {
      if (options.advisorsStatus) return json(res, options.advisorsStatus, { message: 'error' });
      return json(res, 200, options.lints ?? { lints: [] });
    }
    json(res, 404, { message: 'Not Found' });
  };
}

function client(token = VALID_TOKEN) {
  return createManagementClient({ token, baseUrl });
}

async function expectKind(promise: Promise<unknown>, kind: SupabaseApiError['kind']) {
  await assert.rejects(promise, (error: unknown) => {
    assert.ok(error instanceof SupabaseApiError);
    assert.equal(error.kind, kind);
    return true;
  });
}

describe('Supabase Management API client', () => {
  it('正常なプロジェクト: 一覧とAdvisor結果を取得できる', async () => {
    handler = mockSupabase({ lints: LINTS_WITH_ISSUES });
    const projects = await client().listProjects();
    assert.equal(projects.length, 1);
    assert.equal(projects[0]?.ref, PROJECT_A.ref);

    const { findings: lints, issues } = await client().getSecurityAdvisors(PROJECT_A.ref);
    assert.equal(lints.length, 5);
    assert.deepEqual(issues, []);
    assert.deepEqual(lints.map((l) => l.officialSeverity), ['ERROR', 'ERROR', 'WARN', 'INFO', 'WARN']);
    // OpenAPIのenumにない lint 名・metadata.type も落とさずに保持する
    assert.equal(lints[2]?.advisorName, 'public_bucket_allows_listing');
    assert.equal(lints[2]?.resource?.type, 'bucket');
    assert.deepEqual(lints[1]?.metadata.sensitive_columns, ['email', 'phone']);
  });

  it('Advisor結果0件', async () => {
    handler = mockSupabase({ lints: { lints: [] } });
    assert.deepEqual(await client().getSecurityAdvisors(PROJECT_A.ref), { findings: [], issues: [] });
  });

  it('プロジェクトが複数ある', async () => {
    handler = mockSupabase({ projects: [PROJECT_A, PROJECT_B] });
    const projects = await client().listProjects();
    assert.deepEqual(projects.map((p) => p.name), ['my-ai-app', 'side-project']);
  });

  it('無効なトークン → invalid_token', async () => {
    handler = mockSupabase({});
    await expectKind(client('sbp_wrong').listProjects(), 'invalid_token');
  });

  it('権限不足（プロジェクト一覧） → forbidden', async () => {
    handler = mockSupabase({ projectsStatus: 403 });
    await expectKind(client().listProjects(), 'forbidden');
  });

  it('権限不足（Advisors） → forbidden', async () => {
    handler = mockSupabase({ advisorsStatus: 403 });
    await expectKind(client().getSecurityAdvisors(PROJECT_A.ref), 'forbidden');
  });

  it('API障害（500） → server_error', async () => {
    handler = mockSupabase({ advisorsStatus: 500 });
    await expectKind(client().getSecurityAdvisors(PROJECT_A.ref), 'server_error');
  });

  it('レート制限（429） → rate_limited', async () => {
    handler = mockSupabase({ advisorsStatus: 429 });
    await expectKind(client().getSecurityAdvisors(PROJECT_A.ref), 'rate_limited');
  });

  it('API仕様変更（lints が無い） → unexpected_response', async () => {
    handler = mockSupabase({ lints: { results: [] } });
    await expectKind(client().getSecurityAdvisors(PROJECT_A.ref), 'unexpected_response');
  });

  // Phase 2 で仕様変更: 1件の異常で全体を失敗にせず、項目を残したうえで issues に記録する
  it('API仕様変更（level が未知の値） → 項目は残し、issues に unknown_level を記録', async () => {
    handler = mockSupabase({ lints: { lints: [{ ...LINTS_WITH_ISSUES.lints[0], level: 'CRITICAL' }] } });
    const result = await client().getSecurityAdvisors(PROJECT_A.ref);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0]?.officialSeverity, undefined);
    assert.equal(result.findings[0]?.rawLevel, 'CRITICAL');
    assert.deepEqual(result.issues, [{ index: 0, reason: 'unknown_level' }]);
  });

  it('JSONでない応答 → unexpected_response', async () => {
    handler = (_req, res) => {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<html>maintenance</html>');
    };
    await expectKind(client().listProjects(), 'unexpected_response');
  });

  it('プロキシが返す text/plain の 403 は権限不足ではなく network として扱う', async () => {
    handler = (_req, res) => {
      res.writeHead(403, { 'content-type': 'text/plain' });
      res.end('Host not in allowlist: api.supabase.com');
    };
    await expectKind(client().listProjects(), 'network');
  });

  it('ネットワークエラー → network', async () => {
    const c = createManagementClient({ token: VALID_TOKEN, baseUrl: 'http://127.0.0.1:1' });
    await expectKind(c.listProjects(), 'network');
  });

  it('不正なプロジェクトIDは通信せずに弾く', async () => {
    handler = mockSupabase({});
    await expectKind(client().getSecurityAdvisors('../../v1/projects'), 'not_found');
    assert.equal(requests.length, 0);
  });

  it('トークンは Authorization ヘッダーでのみ送る（URLに含めない）', async () => {
    handler = mockSupabase({});
    await client().listProjects();
    assert.equal(requests.length, 1);
    assert.equal(requests[0]?.auth, `Bearer ${VALID_TOKEN}`);
    assert.ok(!requests[0]?.url.includes(VALID_TOKEN));
  });
});

describe('外部通信の制限', () => {
  it('既定の通信先は api.supabase.com のみ', async () => {
    const calledUrls: string[] = [];
    const fakeFetch = (async (input: URL | RequestInfo) => {
      calledUrls.push(String(input));
      return new Response(JSON.stringify([PROJECT_A]), { status: 200 });
    }) as typeof fetch;
    const c = createManagementClient({ token: VALID_TOKEN, fetchImpl: fakeFetch });
    await c.listProjects();
    await c.getSecurityAdvisors(PROJECT_A.ref).catch(() => undefined);
    assert.ok(calledUrls.length >= 2);
    for (const url of calledUrls) assert.equal(new URL(url).origin, SUPABASE_API_ORIGIN);
  });
});

describe('補助関数', () => {
  it('プロジェクトIDの抽出', () => {
    assert.equal(extractProjectRef('abcdefghijklmnopqrst'), 'abcdefghijklmnopqrst');
    assert.equal(extractProjectRef('https://supabase.com/dashboard/project/abcdefghijklmnopqrst/editor'), 'abcdefghijklmnopqrst');
    assert.equal(extractProjectRef('https://abcdefghijklmnopqrst.supabase.co'), 'abcdefghijklmnopqrst');
    assert.equal(extractProjectRef('my-ai-app'), null);
    assert.equal(extractProjectRef('https://evil.example/abcdefghijklmnopqrst'), null);
  });

  it('トークン種別の判定', () => {
    assert.equal(detectTokenKind('sbp_fc0123'), 'scoped');
    assert.equal(detectTokenKind('sbp_0123'), 'classic');
    assert.equal(detectTokenKind('eyJhbGci'), 'unknown');
  });

  it('エラーメッセージは日本語で、全種類に用意されている', () => {
    const kinds: SupabaseApiError['kind'][] = ['invalid_token', 'forbidden', 'not_found', 'rate_limited', 'server_error', 'network', 'unexpected_response'];
    for (const kind of kinds) {
      const message = explainError(new SupabaseApiError(kind, '/x', 'm'), 'advisors');
      assert.match(message, /[ぁ-んァ-ン一-龥]/);
      assert.ok(!message.includes('at '), 'スタックトレースを含めない');
    }
  });
});
