// フォルダ選択 → 技術の自動判定 → 必要なチェックだけ表示 → Supabase なら既存診断へ、の流れのテスト。

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import vm from 'node:vm';
import { after, before, describe, it } from 'node:test';
import { pickerCommands, type PickResult } from '../src/app/folder-picker.js';
import { scanPage } from '../src/app/pages.js';
import { startAppServer, type AppServer } from '../src/app/server.js';
import { buildChecks } from '../src/checks/build.js';
import { chooseMode } from '../src/cli/mode.js';
import { classifySecretValue, parseEnv } from '../src/detect/env.js';
import { isIgnored, parseGitignore } from '../src/detect/gitignore.js';
import { scanProject, ScanError } from '../src/detect/scan.js';
import { SupabaseApiError } from '../src/supabase/errors.js';
import type { SecurityAdvisorResult } from '../src/types/advisor.js';

const REF = 'abcdefghijklmnopqrst';
const TOKEN = 'sbp_fc_SUPER_SECRET_TEST_TOKEN_123456';
const jwt = (payload: object) => `eyJhbGciOiJIUzI1NiJ9.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.c2lnbmF0dXJl`;
const ANON_JWT = jwt({ role: 'anon', ref: REF });
const SERVICE_JWT = jwt({ role: 'service_role', ref: REF });
// 本物の形式に見える値（乱数。リポジトリに本物のキーを置かない）
const OPENAI_KEY = (() => {
  for (;;) {
    const body = randomBytes(96).toString('base64url').replace(/[-_]/g, '').slice(0, 64);
    if (/[A-Z]/.test(body) && /[a-z]/.test(body) && /\d/.test(body) && !/test|fake|dummy|mock|example|sample|canary|fixture|xxxx|your|(.)\1{5,}|0123|1234|2345|abcd/i.test(body)) return `sk-proj-${body}`;
  }
})();

const roots: string[] = [];
after(() => roots.forEach((r) => rmSync(r, { recursive: true, force: true })));

function makeDir(files: Record<string, string>, options: { git?: boolean } = {}): string {
  const root = mkdtempSync(join(tmpdir(), 'kc-app-'));
  roots.push(root);
  if (options.git) mkdirSync(join(root, '.git'));
  for (const [rel, content] of Object.entries(files)) {
    const p = join(root, rel);
    mkdirSync(join(p, '..'), { recursive: true });
    writeFileSync(p, content);
  }
  return root;
}

const pkg = (deps: Record<string, string>, dev: Record<string, string> = {}) => JSON.stringify({ name: 'my-app', dependencies: deps, devDependencies: dev });

// ───────────── 入口 ─────────────

describe('起動方法の振り分け', () => {
  it('引数なしは画面（フォルダ選択）、supabase サブコマンドと従来のオプションはCLI', () => {
    assert.deepEqual(chooseMode([]), { kind: 'app', noOpen: false });
    assert.deepEqual(chooseMode(['--no-open']), { kind: 'app', noOpen: true });
    assert.deepEqual(chooseMode(['supabase', '--project', REF]), { kind: 'cli', argv: ['--project', REF] });
    assert.deepEqual(chooseMode(['--from-file', 'x.json']), { kind: 'cli', argv: ['--from-file', 'x.json'] });
    assert.deepEqual(chooseMode(['--token', 'x']), { kind: 'cli', argv: ['--token', 'x'] }, 'トークン引数の拒否はCLI側で行う');
    assert.deepEqual(chooseMode(['--help']), { kind: 'help' });
  });
});

// ───────────── .env / .gitignore ─────────────

describe('.env の読み取り', () => {
  it('変数名だけを返し、値は保持しない', () => {
    const parsed = parseEnv(
      [
        '# comment',
        `EXPO_PUBLIC_SUPABASE_URL=https://${REF}.supabase.co`,
        `EXPO_PUBLIC_SUPABASE_ANON_KEY="${ANON_JWT}"`,
        `EXPO_PUBLIC_OPENAI_API_KEY=${OPENAI_KEY}`,
        `SUPABASE_SERVICE_ROLE_KEY=${SERVICE_JWT}`,
        'export NEXT_PUBLIC_STRIPE_SECRET=xyz # inline comment',
      ].join('\n'),
    );
    assert.deepEqual(parsed.supabaseRefs, [REF]);
    assert.deepEqual(parsed.keys.map((k) => k.name), ['EXPO_PUBLIC_SUPABASE_URL', 'EXPO_PUBLIC_SUPABASE_ANON_KEY', 'EXPO_PUBLIC_OPENAI_API_KEY', 'SUPABASE_SERVICE_ROLE_KEY', 'NEXT_PUBLIC_STRIPE_SECRET']);
    const json = JSON.stringify(parsed);
    for (const secret of [ANON_JWT, OPENAI_KEY, SERVICE_JWT, 'xyz']) assert.ok(!json.includes(secret), '値が残っている');
    const byName = Object.fromEntries(parsed.keys.map((k) => [k.name, k]));
    assert.equal(byName.EXPO_PUBLIC_OPENAI_API_KEY?.secretLikeValue, 'secret-api-key');
    assert.equal(byName.EXPO_PUBLIC_SUPABASE_ANON_KEY?.secretLikeValue, undefined, 'anon キーは公開用なので問題にしない');
    assert.equal(byName.SUPABASE_SERVICE_ROLE_KEY?.isPublic, false, '公開用でない変数の値は判定しない');
    assert.equal(byName.NEXT_PUBLIC_STRIPE_SECRET?.secretLikeName, true);
  });

  it('秘密のキーの形の判定', () => {
    assert.equal(classifySecretValue('sb_secret_TEST_ONLY_DUMMY'), 'supabase-secret-key');
    assert.equal(classifySecretValue(SERVICE_JWT), 'supabase-service-role-jwt');
    assert.equal(classifySecretValue(ANON_JWT), undefined);
    assert.equal(classifySecretValue('sb_publishable_TEST_ONLY_DUMMY'), undefined);
    assert.equal(classifySecretValue('sk_live_TEST_ONLY_DUMMY_NOT_REAL'), 'secret-api-key');
    assert.equal(classifySecretValue('pk_live_TEST_ONLY_DUMMY_NOT_REAL'), undefined);
    assert.equal(classifySecretValue('https://example.com'), undefined);
  });

  it('.gitignore の簡易判定', () => {
    const rules = [{ base: '', rules: parseGitignore('node_modules\n.env*\n!.env.example\n') }];
    assert.equal(isIgnored('.env', rules), true);
    assert.equal(isIgnored('app/.env.local', rules), true);
    assert.equal(isIgnored('.env.example', rules), false);
    assert.equal(isIgnored('.env', [{ base: '', rules: parseGitignore('dist/\n') }]), false);
    assert.equal(isIgnored('apps/web/.env', [{ base: 'apps/web', rules: parseGitignore('/.env\n') }]), true);
  });
});

// ───────────── 技術の判定 ─────────────

let expoSupabase: string;
let nextFirebase: string;
let plain: string;

before(() => {
  expoSupabase = makeDir(
    {
      'package.json': pkg({ expo: '~52.0.0', 'react-native': '0.76.0', '@supabase/supabase-js': '^2', openai: '^4' }),
      'app.json': JSON.stringify({ expo: { name: 'my-app' } }),
      '.env': [`EXPO_PUBLIC_SUPABASE_URL=https://${REF}.supabase.co`, `EXPO_PUBLIC_SUPABASE_ANON_KEY=${ANON_JWT}`, `EXPO_PUBLIC_OPENAI_API_KEY=${OPENAI_KEY}`].join('\n'),
      '.gitignore': 'node_modules\n',
      'node_modules/firebase/package.json': pkg({ firebase: '1' }),
    },
    { git: true },
  );
  nextFirebase = makeDir(
    {
      'package.json': pkg({ next: '15.0.0', firebase: '^11' }),
      'next.config.mjs': 'export default {}',
      'firebase.json': '{}',
      '.env.local': 'NEXT_PUBLIC_FIREBASE_API_KEY=AIzaPublicKey\nSTRIPE_SECRET_KEY=sk_live_TEST_ONLY_DUMMY_NOT_REAL',
      '.env.example': 'NEXT_PUBLIC_SECRET_TOKEN=\n',
      '.gitignore': '.env*\n!.env.example\n',
    },
    { git: true },
  );
  plain = makeDir({ 'README.md': '# hello' });
});

describe('技術の自動判定', () => {
  it('Expo + React Native + Supabase + 外部API + .env を判定し、プロジェクトIDを見つける', () => {
    const scan = scanProject(expoSupabase);
    assert.deepEqual(scan.techs.map((t) => t.id), ['supabase', 'expo', 'react-native', 'external-api', 'credentials', 'env']);
    assert.deepEqual(scan.supabaseRefs, [REF]);
    assert.deepEqual(scan.externalApis.map((a) => a.name), ['OpenAI']);
    assert.equal(scan.envFiles[0]?.git, 'not-ignored');
    assert.deepEqual(scan.envFiles[0]?.publicSecretKeys, [{ name: 'EXPO_PUBLIC_OPENAI_API_KEY', reason: 'secret-api-key' }]);
    // node_modules の中は見ない（firebase は判定されない）
    assert.ok(!scan.techs.some((t) => t.id === 'firebase'));
    // 結果のどこにも値が含まれない
    const json = JSON.stringify(scan);
    assert.ok(!json.includes(OPENAI_KEY) && !json.includes(ANON_JWT));
  });

  it('Next.js + Firebase（Supabase なし）', () => {
    const scan = scanProject(nextFirebase);
    // STRIPE_SECRET_KEY は秘密情報の定義（Stripe）で扱う（テスト用の値なので、問題としては数えない）
    assert.deepEqual(scan.techs.map((t) => t.id), ['firebase', 'nextjs', 'credentials', 'env']);
    assert.deepEqual(scan.supabaseRefs, []);
    const local = scan.envFiles.find((f) => f.path === '.env.local');
    assert.equal(local?.git, 'ignored');
    assert.deepEqual(local?.publicSecretKeys, [], '公開用でない STRIPE_SECRET_KEY は対象外');
    assert.equal(scan.envFiles.find((f) => f.path === '.env.example')?.isExample, true);
  });

  it('何も判定できないフォルダ', () => {
    assert.deepEqual(scanProject(plain).techs, []);
  });

  it('モノレポ（サブフォルダの package.json）も判定する', () => {
    const mono = makeDir({ 'package.json': pkg({}), 'apps/mobile/package.json': pkg({ expo: '1' }), 'apps/web/package.json': pkg({ next: '1' }) });
    assert.deepEqual(scanProject(mono).techs.map((t) => t.id), ['nextjs', 'expo']);
  });

  it('シンボリックリンクはたどらない', () => {
    const outside = makeDir({ 'package.json': pkg({ '@supabase/supabase-js': '2' }) });
    const root = makeDir({ 'package.json': pkg({}) });
    // Windows ではジャンクション（権限なしで作れるフォルダのリンク。Node.js でもシンボリックリンクとして扱われる）
    symlinkSync(outside, join(root, 'linked'), process.platform === 'win32' ? 'junction' : 'dir');
    assert.deepEqual(scanProject(root).techs, []);
  });

  it('存在しないパス・ファイルはエラー', () => {
    assert.throws(() => scanProject(join(plain, 'nope')), (e: unknown) => e instanceof ScanError && e.kind === 'not-found');
    assert.throws(() => scanProject(join(plain, 'README.md')), (e: unknown) => e instanceof ScanError && e.kind === 'not-directory');
  });

  it('件数の上限を超えたら途中で止める', () => {
    const files: Record<string, string> = { 'package.json': pkg({ next: '1' }) };
    for (let i = 0; i < 50; i++) files[`f${i}.txt`] = 'x';
    const scan = scanProject(makeDir(files), { maxDepth: 4, maxEntries: 10, maxFileBytes: 1024 });
    assert.equal(scan.stats.truncated, true);
  });
});

// ───────────── 必要なチェックだけ ─────────────

describe('必要なチェックだけを表示する', () => {
  it('Supabase を使っていればSupabase診断への案内を出す', () => {
    const checks = buildChecks(scanProject(expoSupabase));
    const ids = checks.map((c) => c.id);
    assert.ok(ids.includes('supabase-advisor'));
    assert.deepEqual(checks.find((c) => c.id === 'supabase-advisor')?.supabase?.refs, [REF]);
    // 公開用の変数に入った秘密のキーは、秘密情報の定義（OpenAI）として1回だけ出す（従来の項目と重ねない）
    assert.ok(ids.includes('secret-openai-danger'));
    assert.ok(!ids.includes('env-public-secret-value'));
    assert.ok(ids.includes('env-not-gitignored'));
    assert.ok(ids.includes('mobile-embedded-keys'));
    assert.ok(ids.includes('external-api-keys'));
    assert.ok(!ids.includes('firebase-rules'));
    assert.ok(!ids.includes('nextjs-public-env'));
  });

  it('Supabase を使っていなければSupabase関連のチェックを出さない', () => {
    const checks = buildChecks(scanProject(nextFirebase));
    const ids = checks.map((c) => c.id);
    assert.ok(!ids.includes('supabase-advisor'));
    assert.ok(!JSON.stringify(checks).includes('Supabase のデータベース'));
    assert.deepEqual(ids.sort(), ['env-gitignored', 'firebase-rules', 'nextjs-public-env', 'secrets-info'].sort());
  });

  it('何も判定できなければチェックは0件', () => {
    assert.deepEqual(buildChecks(scanProject(plain)), []);
  });
});

// ───────────── フォルダ選択画面のコマンド ─────────────

describe('OS標準のフォルダ選択画面', () => {
  it('Windows は PowerShell の FolderBrowserDialog（シェルを経由しない・日本語はエンコードして渡す）', () => {
    const [cmd] = pickerCommands('win32');
    assert.equal(cmd?.command, 'powershell.exe');
    const encoded = cmd?.args[cmd.args.indexOf('-EncodedCommand') + 1] ?? '';
    const script = Buffer.from(encoded, 'base64').toString('utf16le');
    assert.match(script, /FolderBrowserDialog/);
    assert.match(script, /チェックするアプリのフォルダを選んでください/);
  });
  it('macOS は osascript、Linux は zenity → kdialog', () => {
    assert.equal(pickerCommands('darwin')[0]?.command, 'osascript');
    assert.deepEqual(pickerCommands('linux').map((c) => c.command), ['zenity', 'kdialog']);
  });
});

// ───────────── アプリのサーバー ─────────────

interface Res {
  status: number;
  body: string;
  headers: Record<string, string | string[] | undefined>;
}

function http(port: number, path: string, options: { method?: string; body?: string; origin?: string | null; host?: string } = {}): Promise<Res> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = { host: options.host ?? `127.0.0.1:${port}` };
    if (options.body !== undefined) headers['content-type'] = 'application/x-www-form-urlencoded';
    if (options.origin !== null && options.method === 'POST') headers.origin = options.origin ?? `http://127.0.0.1:${port}`;
    const req = request({ hostname: '127.0.0.1', port, path, method: options.method ?? 'GET', headers }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => (body += c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body, headers: res.headers }));
    });
    req.on('error', reject);
    req.end(options.body);
  });
}

/* eslint-disable @typescript-eslint/no-explicit-any */
type FakeListener = { type: string; fn: (ev: any) => void; capture: boolean };
class FakeElement {
  value = '';
  checked = false;
  open = false;
  className = '';
  textContent = '';
  readonly attrs = new Map<string, string>();
  readonly listeners: FakeListener[] = [];
  readonly classList = { add: (_c: string) => undefined, toggle: (_c: string, _on?: boolean) => undefined };
  constructor(readonly id: string) {}
  addEventListener(type: string, fn: (ev: any) => void, capture?: boolean): void {
    this.listeners.push({ type, fn, capture: Boolean(capture) });
  }
  setAttribute(name: string, value: string): void {
    this.attrs.set(name, String(value));
    if (name === 'open') this.open = true;
  }
  getAttribute(name: string): string | null {
    return this.attrs.get(name) ?? null;
  }
  focus(): void {}
  appendChild(_child: unknown): void {}
  showModal(): void {
    this.open = true;
  }
  close(): void {
    this.open = false;
  }
  querySelector(_selector: string): FakeElement | null {
    return null;
  }
}

/** トークン入力画面の <script> を、画面と同じ要素を持つ疑似DOMで動かす（送信は記録するだけで、実際の通信はテストが行う） */
function runTokenPageScript(html: string) {
  const code = html.match(/<script nonce="[^"]+">([\s\S]*?)<\/script>/)?.[1];
  assert.ok(code, 'スクリプトがある');
  const formHtml = html.match(/<form method="post" action="[^"]*supabase\/run"[\s\S]*?<\/form>/)?.[0] ?? '';
  const unescape = (v: string) =>
    v.replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&#96;/g, '`').replace(/&amp;/g, '&');
  const hidden: Record<string, string> = {};
  for (const m of formHtml.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)"/g)) hidden[m[1]!] = unescape(m[2]!);

  const documentListeners: ((ev: any) => void)[] = [];
  const submitted: Record<string, string>[] = [];
  const logs: string[] = [];
  const els = new Map<string, FakeElement>();
  const busy = new FakeElement('busy');
  const allowLegacy = new FakeElement('allowLegacy');
  const fire = (target: FakeElement, type: string) => {
    const ev = {
      type,
      target,
      defaultPrevented: false,
      stopped: false,
      preventDefault() {
        this.defaultPrevented = true;
      },
      stopImmediatePropagation() {
        this.stopped = true;
      },
    };
    for (const capture of [true, false]) {
      for (const l of target.listeners) if (l.type === type && l.capture === capture && !ev.stopped) l.fn(ev);
    }
    if (!ev.stopped && type === 'submit') for (const fn of documentListeners) fn(ev);
    return ev;
  };
  class HTMLFormElement extends FakeElement {
    override querySelector(selector: string): FakeElement | null {
      if (selector === '.busy') return busy;
      if (selector.includes('allowLegacy')) return allowLegacy;
      return null;
    }
    /** 送信ボタンを押したのと同じ（submit イベントを経由する） */
    requestSubmit(): boolean {
      const ev = fire(this, 'submit');
      if (ev.defaultPrevented) return false;
      const fields: Record<string, string> = { ...hidden, token: els.get('token')!.value, connectConfirmed: els.get('connect-confirmed')!.value };
      if (allowLegacy.checked) fields.allowLegacy = '1';
      submitted.push(fields);
      return true;
    }
    submit(): void {
      throw new Error('submit() は確認を飛ばすので使わない');
    }
  }
  for (const id of ['token', 'token-check', 'legacy-confirm', 'connect-dialog', 'connect-confirmed', 'connect-cancel', 'connect-ok']) els.set(id, new FakeElement(id));
  const form = new HTMLFormElement('token-form');
  els.set('token-form', form);
  const record = (...args: unknown[]) => logs.push(args.map(String).join(' '));
  vm.runInNewContext(code, {
    HTMLFormElement,
    setTimeout,
    console: { log: record, info: record, warn: record, error: record, debug: record },
    window: { addEventListener: () => undefined },
    document: {
      getElementById: (id: string) => els.get(id) ?? null,
      createElement: (tag: string) => new FakeElement(tag),
      addEventListener: (type: string, fn: (ev: any) => void) => {
        if (type === 'submit') documentListeners.push(fn);
      },
    },
  });
  return {
    form,
    input: els.get('token')!,
    box: els.get('token-check')!,
    dialog: els.get('connect-dialog')!,
    confirmed: els.get('connect-confirmed')!,
    submitted,
    logs,
    ticket: hidden.connectTicket ?? '',
    submit: () => form.requestSubmit(),
    click: (id: string) => fire(els.get(id)!, 'click'),
  };
}
/* eslint-enable @typescript-eslint/no-explicit-any */

describe('アプリ画面（フォルダ選択 → 判定 → Supabase診断）', () => {
  let server: AppServer;
  let base: string;
  let csrf: string;
  let pickResult: PickResult = { kind: 'cancelled' };
  let quit = 0;
  const calls: { token: string; ref: string }[] = [];
  let advisorResponse: SecurityAdvisorResult | Error = {
    findings: [
      {
        advisorName: 'rls_disabled_in_public',
        title: 'Sample: RLS is off for a public table',
        officialSeverity: 'ERROR',
        categories: ['SECURITY'],
        description: '',
        detail: 'Sample detail: `public.profiles` is reachable from the API and RLS is off.',
        resource: { type: 'table', schema: 'public', name: 'profiles' },
        metadata: {},
        raw: {},
      },
    ],
    issues: [],
  };
  const all: string[] = [];
  const get = async (path: string, opts?: Parameters<typeof http>[2]) => {
    const r = await http(server.port, path, opts);
    all.push(r.body, JSON.stringify(r.headers));
    return r;
  };

  /** 画面で「接続して診断する」を選んだときと同じ、確認済みの印と一回限りの札（画面を開くたびに新しく発行される） */
  const confirmedFields = async () => {
    const page = await get(`${base}supabase?path=${encodeURIComponent(expoSupabase)}`);
    const connectTicket = page.body.match(/name="connectTicket" value="([0-9a-f]{32})"/)?.[1];
    assert.ok(connectTicket, '確認の札がある');
    return { connectConfirmed: '1', connectTicket };
  };

  before(async () => {
    server = await startAppServer({
      nonce: 'n0nce',
      pickFolder: async () => pickResult,
      createClient: (token) => ({
        getSecurityAdvisors: async (ref: string) => {
          calls.push({ token, ref });
          if (advisorResponse instanceof Error) throw advisorResponse;
          return advisorResponse;
        },
      }),
      now: () => new Date('2026-10-07T09:00:00Z'),
      onQuit: () => quit++,
    });
    base = new URL(server.url).pathname;
    const home = await get(base);
    csrf = home.body.match(/name="csrf" value="([0-9a-f]+)"/)?.[1] ?? '';
  });
  after(() => server.close());

  it('ホーム画面はフォルダを選ぶボタンから始まる', async () => {
    const home = await get(base);
    assert.equal(home.status, 200);
    assert.match(home.body, /チェックするアプリのフォルダを選ぶ/);
    assert.doesNotMatch(home.body, /Supabase/, 'ホームに Supabase の説明は出さない');
    assert.match(String(home.headers['content-security-policy']), /form-action 'self'/);
    assert.match(String(home.headers['content-security-policy']), /connect-src 'none'/);
    // no-referrer だとブラウザが Origin: null を送り、フォーム送信が CSRF 対策で弾かれる（実ブラウザで確認した不具合）
    assert.equal(home.headers['referrer-policy'], 'same-origin');
    assert.match(home.body, /<meta name="referrer" content="same-origin">/);
    assert.ok(csrf.length === 48);
  });

  it('フォルダを選ぶ（POST）は、Origin と csrf が正しいときだけ動く', async () => {
    pickResult = { kind: 'picked', path: expoSupabase };
    assert.equal((await get(`${base}pick`, { method: 'POST', body: `csrf=${csrf}`, origin: null })).status, 403);
    assert.equal((await get(`${base}pick`, { method: 'POST', body: `csrf=${csrf}`, origin: 'https://evil.example' })).status, 403);
    assert.equal((await get(`${base}pick`, { method: 'POST', body: 'csrf=wrong' })).status, 403);
    const ok = await get(`${base}pick`, { method: 'POST', body: `csrf=${csrf}` });
    assert.equal(ok.status, 303);
    // 行き先は、選んだフォルダの scan。パスのエンコードの細かな違い（~ を %7E にするか）では比べない
    // （Windows の一時フォルダは C:\Users\RUNNER~1\… のような短い名前になることがある）
    const location = new URL(String(ok.headers.location), 'http://127.0.0.1');
    assert.equal(location.pathname, `${base}scan`);
    assert.deepEqual([...location.searchParams.keys()], ['path']);
    assert.equal(location.searchParams.get('path'), expoSupabase);
  });

  it('選択がキャンセル・使えない場合はホームに戻って案内する', async () => {
    pickResult = { kind: 'cancelled' };
    assert.equal((await get(`${base}pick`, { method: 'POST', body: `csrf=${csrf}` })).headers.location, `${base}?msg=cancelled`);
    pickResult = { kind: 'unavailable' };
    assert.equal((await get(`${base}pick`, { method: 'POST', body: `csrf=${csrf}` })).headers.location, `${base}?msg=unavailable`);
    const home = await get(`${base}?msg=unavailable`);
    assert.match(home.body, /フォルダの場所を貼り付けてください/);
    assert.match(home.body, /<details open>/);
  });

  it('Supabase を使うフォルダ：判定結果と、Supabase のチェックへの案内を出す', async () => {
    const r = await get(`${base}scan?path=${encodeURIComponent(expoSupabase)}`);
    assert.equal(r.status, 200);
    assert.match(r.body, /使われている技術/);
    for (const name of ['Supabase', 'Expo', 'React Native', '外部のAPI', '認証情報', '.env ファイル']) assert.ok(r.body.includes(name), name);
    assert.match(r.body, /Supabase のチェックを始める/);
    assert.match(r.body, /OpenAI の API キーが1か所に直接書かれている可能性があります/);
    assert.ok(!r.body.includes(OPENAI_KEY) && !r.body.includes(ANON_JWT), '.env の値を画面に出さない');
  });

  it('Supabase を使わないフォルダ：Supabase 関連の画面を出さない', async () => {
    const r = await get(`${base}scan?path=${encodeURIComponent(nextFirebase)}`);
    assert.doesNotMatch(r.body, /Supabase のチェック|supabase\?path=/);
    assert.match(r.body, /Firebase のセキュリティルールを確認してください/);
    const direct = await get(`${base}supabase?path=${encodeURIComponent(nextFirebase)}`);
    assert.equal(direct.status, 303, 'URLを直接開いても Supabase の画面は出さない');
    assert.match(String(direct.headers.location), /scan\?path=/);
  });

  it('存在しないフォルダはホームで案内する', async () => {
    const r = await get(`${base}scan?path=${encodeURIComponent(join(plain, 'missing'))}`);
    assert.equal(r.headers.location, `${base}?msg=not-found`);
  });

  it('Supabase：プロジェクトIDは .env から自動で入り、トークンを貼るだけで診断できる', async () => {
    const form = await get(`${base}supabase?path=${encodeURIComponent(expoSupabase)}`);
    assert.match(form.body, new RegExp(`<input type="hidden" name="ref" value="${REF}">`));
    assert.match(form.body, /type="password" id="token" name="token"/);
    assert.match(form.body, /「Advisors」を「Read」/);

    const body = new URLSearchParams({ csrf, path: expoSupabase, ref: REF, token: TOKEN, ...(await confirmedFields()) }).toString();
    const run = await get(`${base}supabase/run`, { method: 'POST', body });
    assert.equal(run.status, 303);
    assert.deepEqual(calls.at(-1), { token: TOKEN, ref: REF });
    const reportPath = String(run.headers.location);
    assert.match(reportPath, new RegExp(`^${base}report/[0-9a-f]{16}$`));

    const report = await get(reportPath);
    assert.match(report.body, /修正してから公開することをおすすめします/);
    assert.match(report.body, /フォルダのチェック結果に戻る/);
    assert.match(report.body, /AIに修正を頼む指示をコピー/);
    const dl = await get(`${reportPath}?download=1`);
    assert.equal(dl.headers['content-disposition'], 'attachment; filename="koukai-check-report.html"');
  });

  it('Supabase：エラー時は日本語で案内し、トークンを画面に戻さない', async () => {
    advisorResponse = new SupabaseApiError('invalid_token', '/v1', 'x', 401);
    const body = new URLSearchParams({ csrf, path: expoSupabase, ref: REF, token: TOKEN, ...(await confirmedFields()) }).toString();
    const r = await get(`${base}supabase/run`, { method: 'POST', body });
    assert.equal(r.status, 200);
    assert.match(r.body, /受け付けられませんでした（無効です）/);
    const empty = await get(`${base}supabase/run`, { method: 'POST', body: new URLSearchParams({ csrf, path: expoSupabase, ref: REF, token: '' }).toString() });
    assert.match(empty.body, /アクセストークンを貼り付けてください/);
  });

  it('Supabase：形の間違ったトークンは、Supabase に問い合わせずに直し方を表示する', async () => {
    const before = calls.length;
    for (const token of ['eyJhbGciOiJIUzI1NiJ9.SUPER_SECRET_TEST_TOKEN', 'sbp_fc_SUPER_SECRET_TEST_TOKEN…', REF]) {
      const r = await get(`${base}supabase/run`, { method: 'POST', body: new URLSearchParams({ csrf, path: expoSupabase, ref: REF, token }).toString() });
      assert.equal(r.status, 200);
      assert.match(r.body, /class="token-check st-danger"/);
    }
    assert.equal(calls.length, before, 'Supabase に問い合わせていない');
  });

  it('Supabase：空白や改行が混ざっていても、取り除いてから問い合わせる', async () => {
    advisorResponse = { findings: [], issues: [] };
    const r = await get(`${base}supabase/run`, { method: 'POST', body: new URLSearchParams({ csrf, path: expoSupabase, ref: REF, token: ` ${TOKEN}\r\n`, ...(await confirmedFields()) }).toString() });
    assert.equal(r.status, 303);
    assert.deepEqual(calls.at(-1), { token: TOKEN, ref: REF });
  });

  it('Supabase：従来型（Legacy）のトークンは、確認の印がなければ使わない', async () => {
    advisorResponse = { findings: [], issues: [] };
    const legacy = 'sbp_SUPER_SECRET_TEST_TOKEN_0123456789abcdef';
    const before = calls.length;
    const first = await get(`${base}supabase/run`, { method: 'POST', body: new URLSearchParams({ csrf, path: expoSupabase, ref: REF, token: legacy }).toString() });
    assert.equal(first.status, 200);
    assert.match(first.body, /おすすめしません/);
    assert.match(first.body, /<p class="legacy-confirm on"/);
    assert.equal(calls.length, before);
    const confirmed = await get(`${base}supabase/run`, { method: 'POST', body: new URLSearchParams({ csrf, path: expoSupabase, ref: REF, token: legacy, allowLegacy: '1', ...(await confirmedFields()) }).toString() });
    assert.equal(confirmed.status, 303);
    assert.equal(calls.at(-1)?.token, legacy);
    const report = await get(String(confirmed.headers.location));
    assert.match(report.body, /このトークンは広い権限を持っています/, 'レポートにも強い権限の注意を出す');
  });

  it('Supabase：403・404 は、何を直せばよいかを表示する', async () => {
    for (const [kind, status, expected] of [
      ['forbidden', 403, /「Advisors」を「Read」/],
      ['not_found', 404, /対象に含めていないプロジェクト/],
    ] as const) {
      advisorResponse = new SupabaseApiError(kind, '/v1', 'x', status);
      const r = await get(`${base}supabase/run`, { method: 'POST', body: new URLSearchParams({ csrf, path: expoSupabase, ref: REF, token: TOKEN, ...(await confirmedFields()) }).toString() });
      assert.equal(r.status, 200);
      assert.match(r.body, /直し方：/);
      assert.match(r.body, expected);
      assert.match(r.body, new RegExp(REF));
    }
  });

  it('Supabase：接続の確認の印がない送信では、api.supabase.com へ接続しない', async () => {
    advisorResponse = { findings: [], issues: [] };
    const before = calls.length;
    for (const connectConfirmed of [undefined, '', '0', 'true']) {
      const fields: Record<string, string> = { csrf, path: expoSupabase, ref: REF, token: TOKEN };
      if (connectConfirmed !== undefined) fields.connectConfirmed = connectConfirmed;
      const r = await get(`${base}supabase/run`, { method: 'POST', body: new URLSearchParams(fields).toString() });
      assert.equal(r.status, 200);
      assert.match(r.body, /Supabase にはまだ接続していません/);
      assert.match(r.body, /<dialog class="confirm" id="connect-dialog"/);
      assert.doesNotMatch(r.body, /class="msg" role="alert"/, 'エラー扱いにしない');
    }
    assert.equal(calls.length, before, 'Supabase に問い合わせていない');
  });

  it('Supabase：接続の確認ダイアログ（キャンセルなら通信0回、「接続して診断する」で既存の診断を1回だけ始める）', async () => {
    advisorResponse = { findings: [], issues: [] };
    const page = await get(`${base}supabase?path=${encodeURIComponent(expoSupabase)}`);
    const dialog = page.body.match(/<dialog class="confirm" id="connect-dialog"[\s\S]*?<\/dialog>/)?.[0] ?? '';
    assert.match(dialog, /<h2 id="connect-title">Supabaseに接続します<\/h2>/);
    assert.match(dialog, /この診断では、Supabase公式API（api\.supabase\.com）へ接続して<br>Security Advisorの結果を取得します。<br>入力したアクセストークンは保存しません。/);
    assert.match(dialog, /type="button" id="connect-cancel">キャンセル<\/button>/);
    assert.match(dialog, /type="button" id="connect-ok">接続して診断する<\/button>/);

    const ui = runTokenPageScript(page.body);
    const before = calls.length;
    ui.input.value = TOKEN;

    // 「チェックする」→ 送信は止まり、確認ダイアログが開く
    assert.equal(ui.submit(), false);
    assert.equal(ui.dialog.open, true);
    assert.equal(ui.submitted.length, 0);

    // キャンセル → 何も送らない（診断を始めない・エラー扱いにしない）
    ui.click('connect-cancel');
    assert.equal(ui.dialog.open, false);
    assert.equal(ui.submitted.length, 0, 'キャンセルでは送信しない');
    assert.equal(ui.confirmed.value, '');
    assert.equal(ui.form.getAttribute('data-busy'), null, '診断中の表示にしない');
    assert.doesNotMatch(ui.box.className, /st-danger/, 'エラー扱いにしない');
    assert.equal(calls.length, before, 'キャンセルでは api.supabase.com へ通信しない');

    // もう一度「チェックする」→「接続して診断する」→ 1回だけ送信される
    assert.equal(ui.submit(), false);
    assert.equal(ui.dialog.open, true);
    ui.click('connect-ok');
    assert.equal(ui.dialog.open, false);
    assert.equal(ui.submitted.length, 1);
    assert.equal(ui.submitted[0]!.connectConfirmed, '1');
    assert.equal(ui.form.getAttribute('data-busy'), '1', '既存の「確認しています…」表示へ進む');

    // 送信された内容を、そのまま実際のサーバーへ送る → 既存の診断が1回だけ始まる
    const run = await get(`${base}supabase/run`, { method: 'POST', body: new URLSearchParams(ui.submitted[0]).toString() });
    assert.equal(run.status, 303);
    assert.equal(calls.length, before + 1);
    assert.deepEqual(calls.at(-1), { token: TOKEN, ref: REF });

    // トークンの値は、ダイアログにもログにも出さない
    assert.ok(!dialog.includes('SUPER_SECRET_TEST_TOKEN'));
    assert.ok(!ui.dialog.textContent.includes('SUPER_SECRET_TEST_TOKEN'));
    assert.deepEqual(ui.logs, [], 'スクリプトはログを出さない');
  });

  it('Supabase：接続の確認は1回限り（再送・並行送信で診断を重ねず、新しい確認なら1回実行できる）', async () => {
    advisorResponse = { findings: [], issues: [] };
    const post = (body: string) => get(`${base}supabase/run`, { method: 'POST', body });
    const openPage = async () => {
      const page = await get(`${base}supabase?path=${encodeURIComponent(expoSupabase)}`);
      const ui = runTokenPageScript(page.body);
      ui.input.value = TOKEN;
      return ui;
    };
    const confirm = (ui: ReturnType<typeof runTokenPageScript>) => {
      assert.equal(ui.submit(), false);
      ui.click('connect-ok');
      assert.equal(ui.submitted.length, 1);
      return new URLSearchParams(ui.submitted[0]).toString();
    };
    const start = calls.length;

    // D. キャンセル → 送信0回・通信0回
    const cancelled = await openPage();
    assert.equal(cancelled.submit(), false);
    cancelled.click('connect-cancel');
    assert.equal(cancelled.submitted.length, 0);
    assert.equal(calls.length, start, 'キャンセルでは通信しない');

    // E. 確認なし（同じ画面の札はあっても、確認の印がない）→ 通信0回
    const ui = await openPage();
    const unconfirmed = new URLSearchParams({ csrf, path: expoSupabase, ref: REF, token: TOKEN, connectTicket: ui.ticket });
    const e1 = await post(unconfirmed.toString());
    assert.equal(e1.status, 200);
    assert.match(e1.body, /Supabase にはまだ接続していません/);
    assert.equal(calls.length, start, '確認前は通信しない');

    // A. 確認 → 正規の送信 → 診断の開始は1回
    const confirmedBody = confirm(ui);
    assert.ok(!ui.ticket.includes('SUPER_SECRET_TEST_TOKEN') && ui.ticket !== TOKEN, '札はトークンと無関係');
    const a = await post(confirmedBody);
    assert.equal(a.status, 303);
    assert.equal(calls.length, start + 1);

    // B. A と同じ確認を再送 → 追加の診断は0回
    for (let i = 0; i < 3; i++) {
      const b = await post(confirmedBody);
      assert.equal(b.status, 200);
      assert.match(b.body, /この確認は、すでに使われたか期限が切れています/);
      assert.doesNotMatch(b.body, /class="msg" role="alert"/, 'エラー扱いにしない');
    }
    assert.equal(calls.length, start + 1, '同じ確認の再送では診断を始めない');

    // C. 新しい確認を、同じ内容で並行送信 → 診断の開始は合計1回
    const parallelBody = confirm(await openPage());
    const results = await Promise.all(Array.from({ length: 6 }, () => post(parallelBody)));
    assert.equal(results.filter((r) => r.status === 303).length, 1, '通るのは1件だけ');
    assert.equal(results.filter((r) => r.status === 200).length, 5);
    assert.equal(calls.length, start + 2, '並行送信でも診断の開始は1回');

    // F. ユーザーがもう一度確認した場合 → 新しい診断は正常に1回実行できる
    const again = await post(confirm(await openPage()));
    assert.equal(again.status, 303);
    assert.equal(calls.length, start + 3);
    assert.deepEqual(calls.at(-1), { token: TOKEN, ref: REF });
  });

  it('Supabase：アプリを起動し直すと、前の起動で出した確認は使えない', async () => {
    const restartedCalls: string[] = [];
    const ui = runTokenPageScript((await get(`${base}supabase?path=${encodeURIComponent(expoSupabase)}`)).body);
    ui.input.value = TOKEN;
    ui.submit();
    ui.click('connect-ok');
    const restarted = await startAppServer({
      nonce: 'n0nce',
      pickFolder: async () => pickResult,
      createClient: () => ({
        getSecurityAdvisors: async (ref: string) => {
          restartedCalls.push(ref);
          return { findings: [], issues: [] };
        },
      }),
      now: () => new Date('2026-10-07T09:00:00Z'),
    });
    try {
      const restartedBase = new URL(restarted.url).pathname;
      const home = await http(restarted.port, restartedBase);
      const restartedCsrf = home.body.match(/name="csrf" value="([0-9a-f]+)"/)?.[1] ?? '';
      const stale = { ...ui.submitted[0], csrf: restartedCsrf };
      const r = await http(restarted.port, `${restartedBase}supabase/run`, { method: 'POST', body: new URLSearchParams(stale).toString() });
      assert.equal(r.status, 200);
      assert.match(r.body, /この確認は、すでに使われたか期限が切れています/);
      assert.deepEqual(restartedCalls, [], '前の起動の確認では接続しない');
    } finally {
      restarted.close();
    }
  });

  it('ローカルの診断（フォルダのチェック）には、接続の確認ダイアログを出さない', async () => {
    const pages = [await get(base)];
    for (const path of [expoSupabase, nextFirebase]) pages.push(await get(`${base}scan?path=${encodeURIComponent(path)}`));
    for (const r of pages) {
      assert.equal(r.status, 200);
      assert.doesNotMatch(r.body, /connect-dialog|Supabaseに接続します|接続して診断する/);
    }
  });

  it('トークンは、どの画面・ヘッダー・リダイレクト先にも含まれない', () => {
    for (const text of all) assert.ok(!text.includes('SUPER_SECRET_TEST_TOKEN'), 'トークンが含まれている');
  });

  it('フォルダ名にHTMLが含まれていてもエスケープする', async () => {
    // 実際のフォルダ：どのOSでもフォルダ名に使える記号（' & ` = ( )）で、属性を壊す名前を作る（Windows では < > " は使えない）
    const name = "x' onmouseover='alert(1)' data-a=`&amp;";
    const evil = makeDir({ [`${name}/package.json`]: pkg({ '@supabase/supabase-js': '2' }) });
    const r = await get(`${base}scan?path=${encodeURIComponent(join(evil, name))}`);
    assert.equal(r.status, 200);
    assert.ok(!r.body.includes("x' onmouseover"), '生の引用符がある');
    assert.ok(r.body.includes('x&#39; onmouseover=&#39;alert(1)&#39; data-a=&#96;&amp;amp;'));
    assert.equal(r.body.match(/<script/g)?.length, 1);

    // タグを含む名前（Linux・macOS ではフォルダ名にできる）：画面を作る処理に直接渡して確かめる
    const scan = scanProject(join(evil, name));
    const tag = '<img src=x onerror=alert(1)>';
    const html = scanPage({ base: '/r/x/', csrf: 'c', nonce: 'n', scan: { ...scan, rootName: tag, root: `/home/u/${tag}` }, checks: buildChecks(scan) });
    assert.ok(!html.includes('<img'), '生のタグがある');
    assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  });

  it('Host が不正・不明なパス・不明なメソッドは拒否する', async () => {
    assert.equal((await get(base, { host: 'evil.example' })).status, 403);
    assert.equal((await get('/')).status, 404);
    assert.equal((await get(`${base}../../etc/passwd`)).status, 404);
    assert.equal((await get(`${base}report/0000000000000000`)).status, 404);
    assert.equal((await get(base, { method: 'DELETE' })).status, 405);
    assert.equal((await get(`${base}pick`, { method: 'POST', body: 'x'.repeat(20_000) })).status, 413);
  });

  it('「終了する」で終了を知らせる', async () => {
    const r = await get(`${base}quit`, { method: 'POST', body: `csrf=${csrf}` });
    assert.match(r.body, /終了しました/);
    assert.equal(quit, 1);
  });
});
