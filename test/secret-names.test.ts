// 秘密情報の検出（定義データ secret-defs.ts を読む共通の仕組み）と重大度のテスト。
// 🔴・🟠にするのは「本物らしい値」が書かれている場合だけ。参照だけ・ダミー・テスト用・公開してよいキーは数えない。
// 値は表示も保持もしない（テストの値がどこにも出ないことを確かめる）。
// 本物らしい値は、テストのたびに乱数で作る（リポジトリに本物の秘密情報を置かないため）。

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { scanPage } from '../src/app/pages.js';
import { buildChecks, secretRisk } from '../src/checks/build.js';
import { parseGitIndex } from '../src/detect/git-index.js';
import { isIgnored, parseGitignore } from '../src/detect/gitignore.js';
import { scanProject } from '../src/detect/scan.js';
import { SECRET_DEFINITIONS } from '../src/detect/secret-defs.js';
import { classifySecretValue, findInEnv, findInText, textPlaceOf } from '../src/detect/secret-names.js';

const BAD = /test|fake|dummy|mock|example|sample|canary|fixture|redacted|invalid|xxxx|your|placeholder|changeme|(.)\1{5,}|0123|1234|2345|abcd|ABCD/i;

/** ランダムな英大小文字・数字（テストの語を含まない） */
function rand(length: number, charset: 'b64' | 'hex' | 'alnum' = 'b64'): string {
  for (;;) {
    let s = randomBytes(length * 2).toString(charset === 'hex' ? 'hex' : 'base64url');
    if (charset === 'alnum') s = s.replace(/[-_]/g, '');
    s = s.slice(0, length);
    const ok = charset === 'hex' ? /\d/.test(s) && /[a-f]/.test(s) : /[A-Z]/.test(s) && /[a-z]/.test(s) && /\d/.test(s);
    if (s.length === length && ok && !BAD.test(s)) return s;
  }
}
const jwt = (payload: object) =>
  `${Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${rand(43)}`;
const pem = () => `-----BEGIN RSA PRIVATE KEY-----\\n${randomBytes(600).toString('base64').match(/.{1,64}/g)?.join('\\n')}\\n-----END RSA PRIVATE KEY-----`;

/** 本物の形式に見える値（乱数） */
const REAL = {
  claude: `sk-ant-oat01-${rand(72)}`,
  anthropic: `sk-ant-api03-${rand(72)}`,
  openai: `sk-proj-${rand(64)}`,
  elevenlabs: `sk_${rand(48, 'hex')}`,
  sbSecret: `sb_secret_${rand(32)}`,
  serviceRole: jwt({ iss: 'supabase', ref: 'abcdefghijklmnopqrst', role: 'service_role', iat: 1700000000, exp: 2000000000 }),
  github: `ghp_${rand(36, 'alnum')}`,
  githubFine: `github_pat_${rand(22, 'alnum')}_${rand(59, 'alnum')}`,
  pem: pem(),
  dbUrl: `postgresql://postgres.abcdefghijklmnopqrst:${rand(24, 'alnum')}@aws-0-ap-northeast-1.pooler.supabase.com:6543/postgres`,
};
/** 公開してよいキー（Supabase） */
const PUBLIC = {
  publishable: `sb_publishable_${rand(32)}`,
  anon: jwt({ iss: 'supabase', ref: 'abcdefghijklmnopqrst', role: 'anon', iat: 1700000000, exp: 2000000000 }),
};
/** テスト用の値 */
const FAKE = 'sk-ant-oat01-SUPER_SECRET_TEST_TOKEN_123456';
/** 値の一部（出力に含まれていないことを確かめる） */
const SECRET_PARTS = [
  REAL.claude.slice(13, 40),
  REAL.anthropic.slice(13, 40),
  REAL.openai.slice(8, 35),
  REAL.elevenlabs.slice(3, 30),
  REAL.sbSecret.slice(10, 35),
  REAL.serviceRole.slice(-30),
  REAL.github.slice(4, 30),
  REAL.githubFine.slice(11, 40),
  REAL.pem.slice(40, 70),
  REAL.dbUrl.slice(44, 60),
  'SUPER_SECRET',
];

const def = (id: string) => SECRET_DEFINITIONS.find((d) => d.id === id) ?? assert.fail(id);

const hasGit = (() => {
  try {
    execFileSync('git', ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();

const roots: string[] = [];
after(() => roots.forEach((r) => rmSync(r, { recursive: true, force: true })));

function project(files: Record<string, string>, options: { git?: 'init' | 'dir'; add?: string[] } = {}): string {
  const root = mkdtempSync(join(tmpdir(), 'kc-secret-'));
  roots.push(root);
  for (const [rel, content] of Object.entries(files)) {
    const path = join(root, ...rel.split('/'));
    mkdirSync(join(path, '..'), { recursive: true });
    writeFileSync(path, content);
  }
  if (options.git === 'init') {
    execFileSync('git', ['init', '-q'], { cwd: root });
    if (options.add?.length) execFileSync('git', ['add', '-f', '--', ...options.add], { cwd: root });
  } else if (options.git === 'dir') {
    mkdirSync(join(root, '.git'));
  }
  return root;
}

/** Git で管理されたファイル（tracked）として置く */
const tracked = (files: Record<string, string>) => project(files, { git: 'init', add: Object.keys(files) });
const checksOf = (root: string) => buildChecks(scanProject(root)).filter((c) => c.tech === 'credentials');
const dangerTitles = (root: string) => checksOf(root).filter((c) => c.status === 'danger').map((c) => c.title);
const statuses = (root: string) => [...new Set(checksOf(root).map((c) => c.status))].sort();

describe('定義データ', () => {
  it('どの定義にも、表示名・環境変数名・形式判定・説明・漏れたときの対処・根拠がある', () => {
    for (const d of SECRET_DEFINITIONS) {
      assert.ok(d.service && d.label && d.envNames.length && d.checks.length && d.description && d.remediation && d.source, d.id);
      for (const n of d.envNames) assert.match(n, /^[A-Z][A-Z0-9_]+$/);
    }
    // 名前に KEY・TOKEN・SECRET を含むだけでは対象にしない（定義の名前は具体的なものだけ）
    assert.ok(!SECRET_DEFINITIONS.some((d) => d.envNames.some((n) => /^(API_KEY|TOKEN|SECRET|KEY)$/.test(n))));
  });

  it('本物の形式の値は、それぞれの定義で「本物らしい」と分類される', () => {
    const cases: [string, string][] = [
      ['claude-code-oauth', REAL.claude],
      ['anthropic', REAL.anthropic],
      ['openai', REAL.openai],
      ['elevenlabs', REAL.elevenlabs],
      ['supabase-secret', REAL.sbSecret],
      ['supabase-secret', REAL.serviceRole],
      ['github', REAL.github],
      ['github', REAL.githubFine],
      ['github-app-private-key', REAL.pem],
      ['database-url', REAL.dbUrl],
    ];
    for (const [id, value] of cases) assert.equal(classifySecretValue(def(id), value).kind, 'real-like', id);
  });
});

describe('Supabase：公開してよいキーを誤って危険にしない', () => {
  it('publishable キー・anon キーは「公開してよいキー」（定義の欄に入っていても漏れとしない）', () => {
    assert.equal(classifySecretValue(def('supabase-secret'), PUBLIC.publishable).kind, 'public');
    assert.equal(classifySecretValue(def('supabase-secret'), PUBLIC.anon).kind, 'public');
  });

  it('NEXT_PUBLIC_ / EXPO_PUBLIC_ に publishable・anon キー（Git で管理）→ 🔴・🟠 にならない。RLS の診断への案内は今までどおり', { skip: !hasGit && 'git がない' }, () => {
    const root = tracked({
      'package.json': JSON.stringify({ dependencies: { '@supabase/supabase-js': '2' } }),
      '.env': `NEXT_PUBLIC_SUPABASE_URL=https://abcdefghijklmnopqrst.supabase.co\nNEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=${PUBLIC.publishable}\nEXPO_PUBLIC_SUPABASE_ANON_KEY=${PUBLIC.anon}\n`,
      'src/supabase.ts': `createClient(url, "${PUBLIC.anon}");\n`,
    });
    const checks = buildChecks(scanProject(root));
    assert.ok(!checks.some((c) => c.status === 'danger' || (c.tech === 'credentials' && c.status === 'warn')), checks.map((c) => c.title).join('\n'));
    assert.ok(checks.some((c) => c.id === 'supabase-advisor'), 'RLS の確認（Supabase の診断）は別に残る');
  });

  it('SUPABASE_SERVICE_ROLE_KEY に anon キーが入っている（名前の付け間違い）→ 公開してよいキーとして扱う', () => {
    const [hit] = findInEnv(`SUPABASE_SERVICE_ROLE_KEY=${PUBLIC.anon}`, '.env', false);
    assert.equal(hit?.value?.kind, 'public');
  });

  it('secret キー・service_role キー：公開用の変数／Git で管理されたソースに直書き → 🔴', { skip: !hasGit && 'git がない' }, () => {
    assert.deepEqual(dangerTitles(project({ '.gitignore': '.env*\n', '.env.local': `NEXT_PUBLIC_SUPABASE_SECRET_KEY=${REAL.sbSecret}\n` }, { git: 'init' })), [
      'Supabase の秘密キー（secret / service_role）が1か所に直接書かれている可能性があります',
    ]);
    // 名前がなくても、値の形（JWT の role が service_role）で見つける
    assert.deepEqual(dangerTitles(tracked({ 'src/admin.ts': `createClient(url, "${REAL.serviceRole}");\n` })), [
      'Supabase の秘密キー（secret / service_role）が1か所に直接書かれている可能性があります',
    ]);
  });

  it('新方式 SUPABASE_SECRET_KEYS（JSON）：secret キーが含まれるかだけを判定し、値は出さない', { skip: !hasGit && 'git がない' }, () => {
    const json = JSON.stringify({ default: REAL.sbSecret, backend: 'sb_secret_TEST_ONLY_DUMMY' });
    const root = tracked({ '.env.example': `SUPABASE_SECRET_KEYS='${json}'\n` });
    assert.deepEqual(dangerTitles(root), ['Supabase の秘密キー（secret / service_role）が1か所に直接書かれている可能性があります']);
    const out = JSON.stringify(scanProject(root)) + JSON.stringify(buildChecks(scanProject(root)));
    assert.ok(!out.includes(REAL.sbSecret.slice(10)) && !out.includes('sb_secret_TEST'), '値を出さない');
    // ダミーだけ・参照だけなら数えない
    assert.deepEqual(statuses(tracked({ '.env.example': `SUPABASE_SECRET_KEYS='{"default":"sb_secret_TEST_ONLY_DUMMY_NOT_REAL"}'\n` })), ['ok']);
    assert.deepEqual(statuses(tracked({ 'src/a.ts': 'const keys = JSON.parse(process.env.SUPABASE_SECRET_KEYS ?? "{}");\n' })), ['ok']);
  });

  it('新方式 SUPABASE_PUBLISHABLE_KEYS・旧方式 SUPABASE_ANON_KEY は公開してよいキー（🔴・🟠 にしない）。ただし秘密の値が入っていれば 🔴', { skip: !hasGit && 'git がない' }, () => {
    const root = tracked({
      '.env.example': [
        `SUPABASE_PUBLISHABLE_KEYS='${JSON.stringify({ default: PUBLIC.publishable })}'`,
        `NEXT_PUBLIC_SUPABASE_ANON_KEY=${PUBLIC.anon}`,
        `SUPABASE_ANON_KEY=${PUBLIC.anon}`,
      ].join('\n'),
    });
    const checks = checksOf(root);
    assert.deepEqual(checks.map((c) => c.status), ['ok']);
    assert.ok(checks[0]?.details?.some((d) => /公開してよいキー 3件/.test(d.summary)));
    // 公開してよいキーの欄に secret キー → 公開されるものとして 🔴
    assert.deepEqual(dangerTitles(tracked({ '.env.example': `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=${REAL.sbSecret}\n` })), [
      'Supabase の秘密キー（secret / service_role）が1か所に直接書かれている可能性があります',
    ]);
    // 参照だけ（公開キーの名前）は何も数えない
    assert.deepEqual(checksOf(tracked({ 'src/a.ts': 'createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);\n' })), []);
  });

  it('旧方式 SUPABASE_SERVICE_ROLE_KEY は秘密のまま', { skip: !hasGit && 'git がない' }, () => {
    assert.deepEqual(dangerTitles(tracked({ '.env.example': `SUPABASE_SERVICE_ROLE_KEY=${REAL.serviceRole}\n` })), [
      'Supabase の秘密キー（secret / service_role）が1か所に直接書かれている可能性があります',
    ]);
  });

  it('ローカル開発用の鍵（iss: supabase-demo）は、それだけでは安全としない（要確認）。複数の根拠がそろえばローカル用', { skip: !hasGit && 'git がない' }, () => {
    const local = jwt({ iss: 'supabase-demo', role: 'service_role', exp: 1983812996 });
    assert.deepEqual(classifySecretValue(def('supabase-secret'), local), { kind: 'uncertain', reason: 'local-unconfirmed' });
    // iss だけ → 🟠（安全扱いしない・🔴 にもしない）
    assert.deepEqual(statuses(tracked({ 'tests/setup.ts': `export const key = "${local}";\n` })), ['warn']);
    // supabase/config.toml だけでは足りない
    assert.deepEqual(statuses(tracked({ 'supabase/config.toml': 'project_id = "x"\n', 'tests/setup.ts': `export const key = "${local}";\n` })), ['warn']);
    // 同じファイルにローカルの URL（127.0.0.1:54321）→ ローカル用（問題に数えない）
    assert.deepEqual(statuses(tracked({ 'tests/setup.ts': `createClient("http://127.0.0.1:54321", "${local}");\n` })), ['ok']);
    // supabase/config.toml ＋ .env にローカルの URL → ローカル用
    const root = project(
      { '.gitignore': '.env*\n', 'supabase/config.toml': 'project_id = "x"\n', '.env.local': 'SUPABASE_URL=http://localhost:54321\n', 'tests/setup.ts': `export const key = "${local}";\n` },
      { git: 'init', add: ['.gitignore', 'supabase/config.toml', 'tests/setup.ts'] },
    );
    assert.deepEqual(statuses(root), ['ok']);
  });
});

describe('サービスごとの判定（共通の仕組み）', () => {
  const services: [string, string, string][] = [
    ['OPENAI_API_KEY', REAL.openai, 'OpenAI の API キーが1か所に直接書かれている可能性があります'],
    ['ANTHROPIC_API_KEY', REAL.anthropic, 'Anthropic（Claude）の API キーが1か所に直接書かれている可能性があります'],
    ['ELEVENLABS_API_KEY', REAL.elevenlabs, 'ElevenLabs の API キーが1か所に直接書かれている可能性があります'],
    ['CLAUDE_CODE_OAUTH_TOKEN', REAL.claude, 'Claude Code の認証トークンが1か所に直接書かれている可能性があります'],
    ['GITHUB_TOKEN', REAL.github, 'GitHub のトークンが1か所に直接書かれている可能性があります'],
    ['SUPABASE_SECRET_KEY', REAL.sbSecret, 'Supabase の秘密キー（secret / service_role）が1か所に直接書かれている可能性があります'],
  ];

  for (const [name, value, title] of services) {
    it(`${name}：本物らしい直書き（tracked）→ 🔴（サービス名＋件数）／参照だけ・ダミー・ignore 済みの .env → 🔴 にならない`, { skip: !hasGit && 'git がない' }, () => {
      assert.deepEqual(dangerTitles(tracked({ 'src/config.ts': `export const ${name} = "${value}";\n` })), [title]);
      assert.deepEqual(statuses(tracked({ 'src/a.ts': `const k = process.env.${name};\n`, 'src/b.ts': `const k = Deno.env.get("${name}");\n` })), ['ok']);
      assert.deepEqual(statuses(tracked({ 'src/a.ts': `export const ${name} = "your-api-key-here";\n` })), ['ok']);
      const ignoredEnv = project({ '.gitignore': '.env*\n', '.env.local': `${name}=${value}\n` }, { git: 'init', add: ['.gitignore'] });
      assert.deepEqual(statuses(ignoredEnv), ['ok']);
    });
  }

  it('名前がなくても、決まった接頭辞の値（sk-ant-・sb_secret_・ghp_・github_pat_）は見つける', () => {
    for (const [value, id] of [
      [REAL.anthropic, 'anthropic'],
      [REAL.claude, 'claude-code-oauth'],
      [REAL.sbSecret, 'supabase-secret'],
      [REAL.github, 'github'],
      [REAL.githubFine, 'github'],
    ] as const) {
      const hits = findInText(`const client = new Client({ key: "${value}" });\n`, 'src/x.ts', 'source');
      assert.deepEqual(hits.map((h) => [h.defId, h.value?.kind, h.as]), [[id, 'real-like', '']], id);
    }
    // OpenAI は接頭辞の種類を公式資料で確かめられなかったため、名前がない場合は探さない
    assert.deepEqual(findInText(`new OpenAI({ apiKey: "${REAL.openai}" })`, 'src/x.ts', 'source'), []);
  });

  it('GitHub：トークンの長さを固定しない（短い・長い・ghs_ の新形式も本物らしいと判断する）', () => {
    const tokens = [
      `ghp_${rand(36, 'alnum')}`,
      `ghp_${rand(80, 'alnum')}`,
      `gho_${rand(40, 'alnum')}`,
      `ghu_${rand(255, 'alnum')}`,
      `ghr_${rand(60, 'alnum')}`,
      `ghs_${rand(36, 'alnum')}`,
      `ghs_123456_${rand(36)}.${rand(120)}.${rand(43)}`, // 2026年からの長い新形式（ghs_APPID_JWT）
      `github_pat_${rand(22, 'alnum')}_${rand(59, 'alnum')}`,
      `github_pat_${rand(120, 'alnum')}`,
    ];
    for (const t of tokens) {
      assert.equal(classifySecretValue(def('github'), t).kind, 'real-like', `${t.slice(0, 4)}… 長さ${t.length}`);
      const hits = findInText(`const token = "${t}";\n`, 'src/x.ts', 'source');
      assert.deepEqual(hits.map((h) => [h.defId, h.value?.kind]), [['github', 'real-like']], `${t.slice(0, 4)}… 長さ${t.length}`);
    }
    assert.notEqual(classifySecretValue(def('github'), 'ghp_TEST_ONLY_DUMMY_NOT_REAL_000000').kind, 'real-like');
  });

  it('GitHub：GitHub Actions のシークレット参照は数えない。GitHub App の秘密鍵の直書き → 🔴', { skip: !hasGit && 'git がない' }, () => {
    assert.deepEqual(statuses(tracked({ '.github/workflows/ci.yml': 'env:\n  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n  GH_TOKEN: ${{ github.token }}\n' })), ['ok']);
    assert.deepEqual(dangerTitles(tracked({ '.env.example': `GITHUB_APP_PRIVATE_KEY="${REAL.pem}"\n` })), ['GitHub App の秘密鍵が1か所に直接書かれている可能性があります']);
    assert.deepEqual(statuses(tracked({ '.env.example': 'GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\\n...\\n-----END RSA PRIVATE KEY-----"\n' })), ['ok']);
  });

  it('DATABASE_URL：名前だけでは秘密としない。パスワード入り・本番の接続先だけを数える', { skip: !hasGit && 'git がない' }, () => {
    const db = (url: string) => findInEnv(`DATABASE_URL=${url}`, '.env.example', true)[0]?.value?.kind;
    assert.equal(db('postgresql://postgres@db.example.co:5432/postgres'), 'placeholder', 'パスワードなし');
    assert.equal(db('postgresql://postgres.abcdefghijklmnopqrst:[YOUR-PASSWORD]@aws-0-ap-northeast-1.pooler.supabase.com:6543/postgres'), 'placeholder');
    assert.equal(db('postgresql://postgres:postgres@localhost:54322/postgres'), 'placeholder');
    assert.equal(db(`postgresql://app:${rand(20, 'alnum')}@localhost:5432/app`), 'test-like', 'ローカル開発用');
    assert.equal(db(REAL.dbUrl), 'real-like');
    assert.deepEqual(dangerTitles(tracked({ '.env.example': `DATABASE_URL=${REAL.dbUrl}\n` })), ['データベースの接続情報（パスワード入り）が1か所に直接書かれている可能性があります']);
    assert.deepEqual(statuses(tracked({ 'prisma/schema.prisma': 'url = env("DATABASE_URL")\n', '.env.example': 'DATABASE_URL=\n' })), ['ok']);
  });

  it('定義にない名前（KEY・TOKEN・SECRET を含むだけ）は、この仕組みでは数えない', () => {
    const hits = findInEnv(`MY_SERVICE_TOKEN=${rand(40)}\nPAYMENT_SECRET=${rand(40)}\nAPI_KEY=${rand(40)}\n`, '.env', false);
    assert.deepEqual(hits, []);
  });
});

describe('参照・ダミー・テスト用の値（CLAUDE_CODE_OAUTH_TOKEN で作った仕組みを共通化）', () => {
  it('参照だけの書き方は値として扱わない', () => {
    for (const text of [
      'const t = process.env.CLAUDE_CODE_OAUTH_TOKEN;',
      'const t = process.env["OPENAI_API_KEY"];',
      'const t = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");',
      'token = os.environ["ANTHROPIC_API_KEY"]',
      'token = os.getenv("ELEVENLABS_API_KEY")',
      'env:\n  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n',
      'export CLAUDE_CODE_OAUTH_TOKEN="$CLAUDE_CODE_OAUTH_TOKEN"',
      'if (!process.env.OPENAI_API_KEY) throw new Error("OPENAI_API_KEY is required");',
    ]) {
      for (const h of findInText(text, 'f', 'source')) {
        assert.notEqual(h.usage, 'literal', text);
        assert.equal(h.value, undefined, text);
      }
    }
  });

  it('テスト用に本物に似せた値・ダミーは、本物らしいとしない（tests フォルダかどうかでは判断しない）', () => {
    const c = def('claude-code-oauth');
    assert.equal(classifySecretValue(c, FAKE).reason, 'test-word');
    assert.equal(classifySecretValue(c, 'sk-ant-oat01-Ab3').reason, 'too-short');
    assert.equal(classifySecretValue(c, `sk-ant-oat01-${'a'.repeat(60)}`).reason, 'low-randomness');
    for (const v of ['', 'xxx', 'your-token-here', '<YOUR_TOKEN>', '********', 'sk-ant-...', 'test-oauth-token']) {
      assert.equal(classifySecretValue(c, v).kind, 'placeholder', v);
    }
    const [hit] = findInText(`const CLAUDE_CODE_OAUTH_TOKEN = "${REAL.claude}";`, 'tests/codex-reviewer.test.mjs', 'source');
    assert.equal(hit?.value?.kind, 'real-like');
  });

  it('探す対象のファイルの種類', () => {
    assert.equal(textPlaceOf('settings.local.json'), 'config');
    assert.equal(textPlaceOf('codex-reviewer.test.mjs'), 'source');
    assert.equal(textPlaceOf('schema.prisma'), undefined);
    assert.equal(textPlaceOf('package-lock.json'), undefined);
    assert.equal(textPlaceOf('README.md'), undefined);
  });
});

describe('Git の状態（.gitignore のフォルダ指定・.git/index）', () => {
  it('フォルダ指定（test-results/）は、その中のファイルにも効く', () => {
    const rules = [{ base: '', rules: parseGitignore('test-results/\n/build\n*.log\n') }];
    assert.equal(isIgnored('test-results/claude-runner-canary.json', rules), true);
    assert.equal(isIgnored('a/test-results/x.json', rules), true);
    assert.equal(isIgnored('build/x.js', rules), true);
    assert.equal(isIgnored('src/build/x.js', rules), false, '/build はルートだけ');
    assert.equal(isIgnored('test-results', rules), false, 'フォルダ指定は同じ名前のファイルには効かない');
  });

  it('index（形式2・4）から、Git が管理しているファイルを読める', { skip: !hasGit && 'git がない' }, () => {
    for (const version of ['2', '4']) {
      const root = project({ 'a.txt': 'x', 'テスト/フォルダ/b.txt': 'y', 'テスト/c.txt': 'z' }, { git: 'init', add: ['.'] });
      execFileSync('git', ['update-index', '--index-version', version], { cwd: root });
      const paths = parseGitIndex(readFileSync(join(root, '.git', 'index')));
      assert.deepEqual([...(paths ?? [])].sort(), ['a.txt', 'テスト/c.txt', 'テスト/フォルダ/b.txt'], `形式${version}`);
    }
  });
});

describe('重大度（共通のルール）', () => {
  it('.gitignore に書かれていても、コミット済み（tracked）なら 🔴', { skip: !hasGit && 'git がない' }, () => {
    const files = { '.gitignore': 'test-results/\n', 'test-results/runner.json': JSON.stringify({ OPENAI_API_KEY: REAL.openai }) };
    const root = tracked(files);
    const hit = scanProject(root).secretNames[0];
    assert.equal(hit?.git, 'tracked');
    assert.equal(hit?.generated, true);
    assert.deepEqual(statuses(root), ['danger']);
  });

  it('untracked で ignore されていない：ソース・設定 → 🔴、.env → 🟠', { skip: !hasGit && 'git がない' }, () => {
    assert.deepEqual(statuses(project({ 'scripts/dev.sh': `ANTHROPIC_API_KEY=${REAL.anthropic} npm run dev\n` }, { git: 'init' })), ['danger']);
    assert.deepEqual(statuses(project({ '.env': `OPENAI_API_KEY=${REAL.openai}\n` }, { git: 'init' })), ['warn']);
  });

  it('Git の対象外のローカルファイル：.env → 問題なし、それ以外 → 🟠。Git なし → 🟠', { skip: !hasGit && 'git がない' }, () => {
    const files = {
      '.gitignore': '.env*\n.claude/settings.local.json\n',
      '.env.local': `CLAUDE_CODE_OAUTH_TOKEN=${REAL.claude}\n`,
      '.claude/settings.local.json': JSON.stringify({ env: { CLAUDE_CODE_OAUTH_TOKEN: REAL.claude } }),
    };
    const scan = scanProject(project(files, { git: 'init', add: ['.gitignore'] }));
    assert.deepEqual(scan.secretNames.map((h) => `${h.file}:${h.git}:${secretRisk(h)}`).sort(), ['.claude/settings.local.json:ignored:warn', '.env.local:ignored:info']);
    assert.deepEqual(statuses(project({ 'src/a.ts': `const OPENAI_API_KEY = "${REAL.openai}";\n` })), ['warn']);
  });

  it('公開用の接頭辞（NEXT_PUBLIC_・EXPO_PUBLIC_ など）に秘密の値 → 🔴（ignore 済みの .env でも）', () => {
    for (const line of [`NEXT_PUBLIC_OPENAI_API_KEY=${REAL.openai}`, `EXPO_PUBLIC_ELEVENLABS_API_KEY=${REAL.elevenlabs}`, `VITE_ANTHROPIC_API_KEY=${REAL.anthropic}`]) {
      const root = project({ '.gitignore': '.env*\n', '.env.local': `${line}\n` }, { git: 'dir' });
      assert.deepEqual(statuses(root), ['danger'], line);
    }
  });

  it('危険の項目には危険な場所だけが入り、参照は別の折りたたみ（ファイル名:行番号だけ）', { skip: !hasGit && 'git がない' }, () => {
    const root = tracked({
      'tests/codex-reviewer.test.mjs': `${'\n'.repeat(532)}const CLAUDE_CODE_OAUTH_TOKEN = "${REAL.claude}";\n`,
      'src/a.ts': 'export const t = process.env.CLAUDE_CODE_OAUTH_TOKEN;\n',
      'src/b.ts': 'export const t = process.env.OPENAI_API_KEY;\n',
    });
    const checks = checksOf(root);
    const danger = checks.find((c) => c.status === 'danger');
    assert.equal(danger?.title, 'Claude Code の認証トークンが1か所に直接書かれている可能性があります');
    assert.deepEqual(danger?.points, ['tests/codex-reviewer.test.mjs:533（ソースコード・本物の形式に見える・Git で管理されている（公開される）・変数名 CLAUDE_CODE_OAUTH_TOKEN）']);
    const info = checks.find((c) => c.id === 'secrets-info');
    assert.deepEqual(info?.details, [
      { summary: 'Claude Code の認証トークン：参照している場所 1件（値は書かれていない）', items: ['src/a.ts:1'] },
      { summary: 'OpenAI の API キー：参照している場所 1件（値は書かれていない）', items: ['src/b.ts:1'] },
    ]);
  });
});

describe('画面の表示', () => {
  it('分類名は「認証情報」。一般的な API キーの案内は、定義にないキーがあるときだけ', () => {
    const root = project({ '.env': `OPENAI_API_KEY=${FAKE}\n`, 'src/a.ts': 'process.env.CLAUDE_CODE_OAUTH_TOKEN\n' });
    const scan = scanProject(root);
    assert.ok(scan.techs.some((t) => t.id === 'credentials'));
    const checks = buildChecks(scan);
    assert.ok(checks.filter((c) => c.id.startsWith('secret')).every((c) => c.tech === 'credentials'));
    assert.equal(checks.find((c) => c.id === 'external-api-keys'), undefined);
    const html = scanPage({ base: '/r/x/', csrf: 'c', nonce: 'n', scan, checks });
    assert.match(html, /<p class="target">認証情報<\/p>/);
    assert.doesNotMatch(html, /<p class="target">外部のAPI<\/p>/);

    const withOther = buildChecks(scanProject(project({ '.env': `RESEND_API_KEY=x\nOPENAI_API_KEY=${FAKE}\n` })));
    assert.deepEqual(withOther.find((c) => c.id === 'external-api-keys')?.points, ['Resend（RESEND_API_KEY）']);
  });

  it('折りたたみの中は「ファイル名:行番号」を本文の文字として1件ずつ。空の行・箇条書き・属性は使わない。0件なら出さない', () => {
    const root = project({ 'src/a.ts': 'process.env.CLAUDE_CODE_OAUTH_TOKEN\n', 'tests/b.test.mjs': `\n\nconst CLAUDE_CODE_OAUTH_TOKEN = "${FAKE}";\n` });
    const scan = scanProject(root);
    const html = scanPage({ base: '/r/x/', csrf: 'c', nonce: 'n', scan, checks: buildChecks(scan) });
    assert.match(html, /<div class="locs"><div class="loc">src\/a\.ts:1<\/div><\/div>/);
    assert.match(html, /<div class="locs"><div class="loc">tests\/b\.test\.mjs:3<\/div><\/div>/);
    for (const block of html.match(/<details class="more">[\s\S]*?<\/details>/g) ?? []) {
      assert.doesNotMatch(block, /<ul|<li|data-|title=/);
      assert.doesNotMatch(block, /<div class="loc">\s*<\/div>/);
    }
    assert.doesNotMatch(html, /\.locs?[^{]*::?(before|after)/);
    assert.match(html, /\.loc\{[^}]*color:inherit/);
    const noRefs = scanProject(project({ 'tests/b.test.mjs': `const CLAUDE_CODE_OAUTH_TOKEN = "${FAKE}";\n` }));
    assert.doesNotMatch(scanPage({ base: '/r/x/', csrf: 'c', nonce: 'n', scan: noRefs, checks: buildChecks(noRefs) }), /参照している場所/);
  });

  it('値は、判定結果・チェック・画面のどこにも出ない（すべての定義）', { skip: !hasGit && 'git がない' }, () => {
    const files: Record<string, string> = {
      '.gitignore': '.env*\n',
      '.env.local': Object.entries({ CLAUDE_CODE_OAUTH_TOKEN: REAL.claude, ANTHROPIC_API_KEY: REAL.anthropic, NEXT_PUBLIC_OPENAI_API_KEY: REAL.openai, ELEVENLABS_API_KEY: REAL.elevenlabs, DATABASE_URL: REAL.dbUrl })
        .map(([k, v]) => `${k}=${v}`)
        .join('\n'),
      'src/a.ts': `const a = "${REAL.sbSecret}";\nconst b = "${REAL.serviceRole}";\nconst c = "${REAL.github}";\nconst d = "${REAL.githubFine}";\nconst e = "${FAKE}";\n`,
      '.env.example': `GITHUB_APP_PRIVATE_KEY="${REAL.pem}"\n`,
    };
    const root = project(files, { git: 'init', add: ['src/a.ts', '.gitignore', '.env.example'] });
    const scan = scanProject(root);
    const checks = buildChecks(scan);
    const html = scanPage({ base: '/r/x/', csrf: 'c', nonce: 'n', scan, checks });
    assert.ok(checks.filter((c) => c.status === 'danger').length >= 4);
    for (const text of [JSON.stringify(scan), JSON.stringify(checks), html]) {
      for (const part of SECRET_PARTS) assert.ok(!text.includes(part), `値が含まれている（${part.slice(0, 4)}…）`);
      assert.ok(!/sk-ant-oat01|sk-proj-|sb_secret_[A-Za-z0-9]|ghp_[A-Za-z0-9]|github_pat_[A-Za-z0-9]|BEGIN RSA/.test(text));
    }
  });
});
