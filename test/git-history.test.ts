// Git の履歴（過去のコミット）に残った秘密情報のチェックのテスト。
// 値はテストのたびに乱数で作る。値・鍵が、結果・チェック・画面・ログに出ないこと、リポジトリを書き換えないことも確かめる。

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, describe, it } from 'node:test';
import { pathToFileURL } from 'node:url';
import { scanPage } from '../src/app/pages.js';
import { buildChecks, type CheckItem } from '../src/checks/build.js';
import { findGitExecutable } from '../src/detect/git-history.js';
import { scanProject, type ScanOptions } from '../src/detect/scan.js';

const BAD = /test|fake|dummy|mock|example|sample|canary|fixture|redacted|invalid|xxxx|your|placeholder|changeme|(.)\1{5,}|0123|1234|2345|abcd|ABCD/i;
function rand(length: number): string {
  for (;;) {
    const s = randomBytes(length * 2).toString('base64url').replace(/[-_]/g, '').slice(0, length);
    if (s.length === length && /[A-Z]/.test(s) && /[a-z]/.test(s) && /\d/.test(s) && !BAD.test(s)) return s;
  }
}
const stripe = () => `sk_live_${rand(99)}`;
const awsSecret = () => {
  for (;;) {
    const s = randomBytes(30).toString('base64');
    if (/[A-Z]/.test(s) && /[a-z]/.test(s) && /\d/.test(s) && !BAD.test(s)) return s;
  }
};
const KEY = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

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
function tempDir(): string {
  const d = mkdtempSync(join(tmpdir(), 'kc-hist-'));
  roots.push(d);
  return d;
}

const GIT_ID = ['-c', 'user.name=koukai-check test', '-c', 'user.email=test@koukai-check.invalid', '-c', 'commit.gpgsign=false', '-c', 'core.autocrlf=false'];
function git(cwd: string, ...args: string[]): string {
  return execFileSync('git', [...GIT_ID, ...args], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}
function write(root: string, rel: string, content: string): void {
  const p = join(root, ...rel.split('/'));
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, content);
}
/** ファイルを書いてコミットする（null は削除） */
function commit(root: string, files: Record<string, string | null>, message = 'change'): void {
  for (const [rel, content] of Object.entries(files)) {
    if (content === null) git(root, 'rm', '-q', '--', rel);
    else write(root, rel, content);
  }
  git(root, 'add', '-A');
  git(root, 'commit', '-q', '--allow-empty', '-m', message);
}
function repo(): string {
  const root = tempDir();
  git(root, 'init', '-q');
  write(root, 'package.json', '{"name":"app"}');
  return root;
}
/** 裸のリポジトリを origin にして push する（push 済みの履歴を作る） */
function pushToRemote(root: string): void {
  const remote = tempDir();
  git(remote, 'init', '-q', '--bare');
  git(root, 'remote', 'add', 'origin', remote);
  git(root, 'push', '-q', 'origin', 'HEAD:refs/heads/main');
}

const scan = (root: string, options: ScanOptions = {}) => scanProject(root, undefined, options);
const ids = (list: CheckItem[]) => list.map((c) => c.id);
const byId = (list: CheckItem[], id: string) => list.find((c) => c.id === id);

/** 値が、結果・チェック・画面・ログに出ないこと */
function assertNoValue(root: string, values: string[], options: ScanOptions = {}) {
  const logs: string[] = [];
  const saved = { log: console.log, error: console.error, warn: console.warn, info: console.info };
  for (const k of ['log', 'error', 'warn', 'info'] as const) console[k] = (...args: unknown[]) => void logs.push(args.map(String).join(' '));
  let result, list, html;
  try {
    result = scan(root, options);
    list = buildChecks(result);
    html = scanPage({ base: '/r/x/', csrf: 'c', nonce: 'n', scan: result, checks: list });
  } finally {
    Object.assign(console, saved);
  }
  for (const text of [JSON.stringify(result), JSON.stringify(list), html, logs.join('\n')]) {
    for (const v of values) for (const part of [v.slice(8, 40), v.slice(-24)]) assert.ok(!text.includes(part), `値が含まれている（${part.slice(0, 4)}…）`);
    assert.ok(!/BEGIN [A-Z ]*PRIVATE KEY|sk_live_[A-Za-z0-9]/.test(text));
    assert.ok(!/fingerprint|hmac/i.test(text), '指紋が結果に入っている');
  }
  return { result, list };
}

/** .git の中のファイルの一覧と大きさ（書き換えていないことを確かめる） */
function snapshot(dir: string): string {
  const walk = (d: string): string[] => readdirSync(d).sort().flatMap((n) => {
    const p = join(d, n);
    const st = statSync(p);
    return st.isDirectory() ? walk(p) : [`${p}:${st.size}:${st.mtimeMs}`];
  });
  return walk(join(dir, '.git')).join('\n');
}

describe('Git の履歴に残った秘密情報', { skip: !hasGit && 'git がない', timeout: 120_000 }, () => {
  it('positive：消したファイルの過去のコミットにある本物らしい値を見つける（リモートなし → 🟠）', () => {
    const root = repo();
    const value = stripe();
    commit(root, { 'src/pay.ts': `export const k = "${value}";\n` }, 'add key');
    commit(root, { 'src/pay.ts': null }, 'remove key');
    const { result, list } = assertNoValue(root, [value]);
    assert.equal(result.gitHistory.status, 'checked');
    assert.equal(result.gitHistory.findings.length, 1);
    const f = result.gitHistory.findings[0];
    assert.deepEqual([f?.kind, f?.defId, f?.file, f?.pushed, f?.value], ['secret', 'stripe', 'src/pay.ts', 'no-remote', 'real-like']);
    assert.match(f?.commit ?? '', /^[0-9a-f]{7}$/);
    assert.match(byId(list, 'git-history-warn')?.points?.[0] ?? '', /^Stripe の秘密キー（シークレットキー・制限付きキー）：src\/pay\.ts（コミット [0-9a-f]{7}（\d{4}-\d{2}-\d{2}）で追加・リモートなし）$/);
    // いまのファイルにはないので、いまのファイルの項目には出ない
    assert.ok(!ids(list).includes('secret-stripe-danger'));
  });

  it('push 済みの履歴に残っていれば 🔴。まだ push していないコミットなら 🟠', () => {
    const root = repo();
    const pushed = stripe();
    commit(root, { 'config/keys.json': JSON.stringify({ STRIPE_SECRET_KEY: pushed }) }, 'add');
    commit(root, { 'config/keys.json': null }, 'remove');
    pushToRemote(root);
    const local = awsSecret();
    commit(root, { 'src/s3.ts': `const c = { secretAccessKey: "${local}" };\n` }, 'local only');
    commit(root, { 'src/s3.ts': null }, 'remove local');
    const { result, list } = assertNoValue(root, [pushed, local]);
    const byDef = Object.fromEntries(result.gitHistory.findings.map((f) => [f.defId, f.pushed]));
    assert.deepEqual(byDef, { stripe: 'yes', 'aws-secret-access-key': 'no' });
    assert.equal(byId(list, 'git-history-danger')?.points?.length, 1);
    assert.match(byId(list, 'git-history-danger')?.points?.[0] ?? '', /config\/keys\.json.*push 済み/);
    assert.match(byId(list, 'git-history-warn')?.points?.[0] ?? '', /src\/s3\.ts.*まだ push していない/);
    assert.match(byId(list, 'git-history-danger')?.body ?? '', /このツールは履歴を書き換えません/);
  });

  it('同じ値は1件にまとめる（ほかのファイル・ほかのコミットの分は「ほかに N か所」）', () => {
    const root = repo();
    const value = stripe();
    // 中身がまったく同じファイルは Git の中で1つの版になるため、b.ts は中身を変えて別の版にする
    commit(root, { 'a.ts': `const k = "${value}";\n`, 'b.ts': `const other = "${value}";\n` });
    commit(root, { 'a.ts': `const k = "${value}"; // 1\n` });
    commit(root, { 'a.ts': null, 'b.ts': null });
    const { result } = assertNoValue(root, [value]);
    assert.equal(result.gitHistory.findings.length, 1);
    assert.equal(result.gitHistory.findings[0]?.occurrences, 3);
    assert.equal(result.gitHistory.findings[0]?.otherFiles.length, 1);
  });

  it('いまのファイルにまだある値は、履歴では数えない（いまのファイルの項目で知らせる）', () => {
    const root = repo();
    const value = stripe();
    commit(root, { 'src/pay.ts': `export const k = "${value}";\n` });
    commit(root, { 'src/pay.ts': `export const k = "${value}";\nexport const x = 1;\n` });
    const { result, list } = assertNoValue(root, [value]);
    assert.deepEqual(result.gitHistory.findings, []);
    assert.ok(ids(list).includes('secret-stripe-danger'));
    assert.ok(!ids(list).some((id) => id === 'git-history-danger' || id === 'git-history-warn'));
    assert.equal(byId(list, 'git-history-ok')?.status, 'ok');
  });

  it('negative / dummy / safe：テスト用の値・公開してよいキー・参照だけは、履歴にあっても数えない', () => {
    const root = repo();
    commit(root, {
      'src/a.ts': [
        'const t = "sk_live_TEST_ONLY_DUMMY_NOT_REAL_000000000000";',
        `const pk = "pk_live_${rand(99)}";`,
        'const s = process.env.STRIPE_SECRET_KEY;',
        `const tst = "sk_test_${rand(99)}";`,
      ].join('\n'),
    });
    commit(root, { 'src/a.ts': null });
    const { result, list } = assertNoValue(root, []);
    assert.deepEqual(result.gitHistory.findings, []);
    assert.equal(byId(list, 'git-history-ok')?.status, 'ok');
  });

  it('秘密鍵のファイル・.env も、消したあとの履歴から見つける', () => {
    const root = repo();
    const aws = awsSecret();
    commit(root, { 'keys/server.pem': KEY, '.env': `AWS_SECRET_ACCESS_KEY=${aws}\n` });
    commit(root, { 'keys/server.pem': null, '.env': null });
    const { result } = assertNoValue(root, [aws, KEY.split('\n')[2] ?? '']);
    const kinds = result.gitHistory.findings.map((f) => `${f.kind}:${f.defId ?? f.keyKind}:${f.file}`).sort();
    assert.deepEqual(kinds, ['private-key:pem:keys/server.pem', 'secret:aws-secret-access-key:.env']);
  });

  it('git が見つからないときは、履歴のチェックだけを飛ばし、ほかのチェックは行う（アプリ全体は失敗しない）', () => {
    const root = repo();
    const value = stripe();
    commit(root, { 'src/pay.ts': `export const k = "${value}";\n` });
    const { result, list } = assertNoValue(root, [value], { history: { git: null } });
    assert.equal(result.gitHistory.status, 'no-git-command');
    assert.equal(byId(list, 'git-history-skipped')?.status, 'manual');
    assert.ok(ids(list).includes('secret-stripe-danger'), 'いまのファイルのチェックは行っている');
  });

  it('Git で管理していないフォルダ・.git が壊れているフォルダでは、履歴の項目を出さない', () => {
    const plain = tempDir();
    write(plain, 'package.json', '{}');
    assert.equal(scan(plain).gitHistory.status, 'not-repo');
    const broken = tempDir();
    mkdirSync(join(broken, '.git'));
    write(broken, 'package.json', '{}');
    const r = scan(broken);
    assert.equal(r.gitHistory.status, 'not-repo');
    assert.ok(!ids(buildChecks(r)).some((id) => id.startsWith('git-history')));
  });

  it('上限（ファイルの版の数）に達したら、一部だけを調べたと伝える', () => {
    const root = repo();
    const value = stripe();
    commit(root, { 'a.ts': 'const a = 1;\n', 'b.ts': 'const b = 2;\n', 'c.ts': `const k = "${value}";\n` });
    commit(root, { 'c.ts': null });
    const r = scan(root, { history: { limits: { maxBlobs: 1, maxBytes: 1024 * 1024, maxFileBytes: 1024 * 1024, maxMillis: 20_000, maxFindings: 50 } } });
    assert.equal(r.gitHistory.truncated, true);
    assert.equal(r.gitHistory.stats.blobs, 1);
    const card = buildChecks(r).find((c) => c.id.startsWith('git-history'));
    assert.match(card?.body ?? '', /一部だけを確認しました/);
  });

  it('選んだフォルダがリポジトリの一部なら、その中の履歴だけを調べる', () => {
    const root = repo();
    const inside = stripe();
    const outside = stripe();
    commit(root, { 'apps/web/package.json': '{}', 'apps/web/src/a.ts': `const k = "${inside}";\n`, 'apps/other/a.ts': `const k = "${outside}";\n` });
    commit(root, { 'apps/web/src/a.ts': null, 'apps/other/a.ts': null });
    const r = scan(join(root, 'apps', 'web'));
    assert.deepEqual(r.gitHistory.findings.map((f) => f.file), ['src/a.ts']);
  });

  it('一部だけを取得したリポジトリ（partial clone）では、通信しないよう履歴を読まない（オブジェクトが増えない）', () => {
    const src = repo();
    const value = stripe();
    commit(src, { 'src/pay.ts': `export const k = "${value}";\n` });
    commit(src, { 'src/pay.ts': null });
    git(src, 'config', 'uploadpack.allowFilter', 'true');
    const clone = join(tempDir(), 'clone');
    git(dirname(clone), 'clone', '-q', '--no-local', '--filter=blob:none', pathToFileURL(src).href, clone);
    const objects = () => git(clone, 'count-objects', '-v').split('\n').filter((l) => /^(count|in-pack):/.test(l)).join(' ');
    const before = objects();
    const r = scan(clone);
    assert.deepEqual([r.gitHistory.status, r.gitHistory.reason], ['failed', 'partial-clone']);
    const card = byId(buildChecks(r), 'git-history-skipped');
    assert.equal(card?.status, 'manual');
    assert.match(card?.body ?? '', /通信しないよう/);
    assert.equal(objects(), before, 'リモートからオブジェクトを取りに行っていない');
  });

  it('リポジトリを書き換えない（.git の中のファイルが変わらない）', () => {
    const root = repo();
    const value = stripe();
    commit(root, { 'src/pay.ts': `export const k = "${value}";\n` });
    commit(root, { 'src/pay.ts': null });
    const before = snapshot(root);
    scan(root);
    assert.equal(snapshot(root), before);
  });
});

describe('git の実行ファイルの探し方', () => {
  it('PATH から絶対パスで探し、調べるフォルダの中・相対パスの場所は使わない', () => {
    const root = tempDir();
    const outsideBin = tempDir();
    const exe = process.platform === 'win32' ? 'git.exe' : 'git';
    // 調べるフォルダの中に置かれた git（悪意のあるリポジトリを想定）
    write(root, exe, 'not a real git');
    write(root, `bin/${exe}`, 'not a real git');
    write(outsideBin, exe, 'stand-in');
    const sep = process.platform === 'win32' ? ';' : ':';
    assert.equal(findGitExecutable(root, ['.', 'bin', root, join(root, 'bin')].join(sep)), undefined);
    assert.equal(findGitExecutable(root, [root, '.', outsideBin].join(sep)), join(outsideBin, exe));
    assert.equal(findGitExecutable(root, ''), undefined);
  });
});
