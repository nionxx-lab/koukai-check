// 公開事故チェックの追加4項目のテスト：Firebase のセキュリティルール／秘密鍵・サービスアカウント鍵／公開フォルダ／Stripe・AWS。
// 本物らしい鍵・値は、テストのたびに作る（リポジトリに本物の秘密情報を置かない）。値・鍵が、結果・画面・ログに出ないことも確かめる。

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { scanPage } from '../src/app/pages.js';
import { buildChecks, type CheckItem } from '../src/checks/build.js';
import { analyzeDatabaseRules, analyzeServiceRules } from '../src/detect/firebase-rules.js';
import { findPrivateKey } from '../src/detect/key-files.js';
import { scanProject } from '../src/detect/scan.js';
import { SECRET_DEFINITIONS } from '../src/detect/secret-defs.js';
import { classifySecretValue } from '../src/detect/secret-names.js';

const NOW = new Date('2026-10-10T00:00:00Z');
const BAD = /test|fake|dummy|mock|example|sample|canary|fixture|redacted|invalid|xxxx|your|placeholder|changeme|(.)\1{5,}|0123|1234|2345|abcd|ABCD/i;

function rand(length: number, charset: 'alnum' | 'b64std' = 'alnum'): string {
  for (;;) {
    let s = randomBytes(length * 2).toString(charset === 'b64std' ? 'base64' : 'base64url');
    if (charset === 'alnum') s = s.replace(/[-_]/g, '');
    else s = s.replace(/=/g, '');
    s = s.slice(0, length);
    if (s.length === length && /[A-Z]/.test(s) && /[a-z]/.test(s) && /\d/.test(s) && !BAD.test(s)) return s;
  }
}

const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const KEYS = {
  pkcs8: rsa.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  pkcs1: rsa.privateKey.export({ type: 'pkcs1', format: 'pem' }).toString(),
  ec: ec.privateKey.export({ type: 'sec1', format: 'pem' }).toString(),
  encrypted: rsa.privateKey.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: 'pass-phrase-for-unit' }).toString(),
  openssh: `-----BEGIN OPENSSH PRIVATE KEY-----\n${Buffer.concat([Buffer.from('openssh-key-v1\0', 'latin1'), randomBytes(300)]).toString('base64').match(/.{1,70}/g)?.join('\n')}\n-----END OPENSSH PRIVATE KEY-----\n`,
  publicKey: rsa.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
};
const CERT = `-----BEGIN CERTIFICATE-----\n${randomBytes(600).toString('base64').match(/.{1,64}/g)?.join('\n')}\n-----END CERTIFICATE-----\n`;
/** 形はそれらしいが、本体が鍵の形をしていない（ダミー） */
const BROKEN_KEY = `-----BEGIN PRIVATE KEY-----\n${'QUJD'.repeat(80)}\n-----END PRIVATE KEY-----\n`;
const DUMMY_KEY = `-----BEGIN PRIVATE KEY-----\nMIIEvDUMMYKEYFORTESTSONLY${'A'.repeat(200)}\n-----END PRIVATE KEY-----\n`;
const SERVICE_ACCOUNT = JSON.stringify(
  {
    type: 'service_account',
    project_id: 'my-app-12345',
    private_key_id: randomBytes(20).toString('hex'),
    private_key: KEYS.pkcs8,
    client_email: 'firebase-adminsdk@my-app-12345.iam.gserviceaccount.com',
    client_id: '1'.repeat(3) + randomBytes(8).readUInt32BE(0),
  },
  null,
  2,
);

const STRIPE = {
  secret: `sk_live_${rand(99)}`,
  restricted: `rk_live_${rand(99)}`,
  publishable: `pk_live_${rand(99)}`,
  sandbox: `sk_test_${rand(99)}`,
};
const AWS = { secret: rand(40, 'b64std'), id: `AKIA${rand(16).toUpperCase()}` };
const OAUTH_SECRET = `GOCSPX-${rand(28)}`;

/** 値・鍵の一部（どこにも出ないことを確かめる） */
const SECRET_PARTS = [
  ...[KEYS.pkcs8, KEYS.pkcs1, KEYS.ec, KEYS.encrypted, KEYS.openssh].map((k) => k.split('\n')[2] ?? ''),
  STRIPE.secret.slice(8, 40),
  STRIPE.restricted.slice(8, 40),
  AWS.secret.slice(0, 30),
  OAUTH_SECRET.slice(7),
].filter((x) => x.length >= 20);

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

function project(files: Record<string, string | Buffer>, options: { git?: 'init' | 'none'; add?: string[] } = {}): string {
  const root = mkdtempSync(join(tmpdir(), 'kc-exposure-'));
  roots.push(root);
  for (const [rel, content] of Object.entries(files)) {
    const path = join(root, ...rel.split('/'));
    mkdirSync(join(path, '..'), { recursive: true });
    writeFileSync(path, content);
  }
  if (options.git !== 'none') {
    execFileSync('git', ['init', '-q'], { cwd: root });
    if (options.add?.length) execFileSync('git', ['add', '-f', '--', ...options.add], { cwd: root });
  }
  return root;
}
const tracked = (files: Record<string, string | Buffer>) => project(files, { add: Object.keys(files) });
const checks = (root: string) => buildChecks(scanProject(root, undefined, { now: NOW }));
const byId = (list: CheckItem[], id: string) => list.find((c) => c.id === id);
const ids = (list: CheckItem[]) => list.map((c) => c.id);
const dangerOrWarn = (list: CheckItem[]) => list.filter((c) => c.status === 'danger' || c.status === 'warn');

/** 値が、結果・チェック・画面・ログのどこにも出ないこと */
function assertNoValues(root: string) {
  const logs: string[] = [];
  const saved = { log: console.log, error: console.error, warn: console.warn, info: console.info };
  for (const k of ['log', 'error', 'warn', 'info'] as const) console[k] = (...args: unknown[]) => void logs.push(args.map(String).join(' '));
  let scan, list, html;
  try {
    scan = scanProject(root, undefined, { now: NOW });
    list = buildChecks(scan);
    html = scanPage({ base: '/r/x/', csrf: 'c', nonce: 'n', scan, checks: list });
  } finally {
    Object.assign(console, saved);
  }
  for (const text of [JSON.stringify(scan), JSON.stringify(list), html, logs.join('\n')]) {
    for (const part of SECRET_PARTS) assert.ok(!text.includes(part), `値が含まれている（${part.slice(0, 4)}…）`);
    assert.ok(!/BEGIN [A-Z ]*PRIVATE KEY|sk_live_[A-Za-z0-9]|rk_live_[A-Za-z0-9]|GOCSPX-/.test(text));
  }
  return { scan, list, html };
}

// ───────────── 1. Firebase のセキュリティルール ─────────────

const firestore = (body: string) => `rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n${body}\n  }\n}\n`;
const ALL = (rule: string) => firestore(`    match /{document=**} {\n      ${rule}\n    }`);

describe('1. Firebase のセキュリティルール', () => {
  it('positive：全体に if true（Firestore・Storage）・条件なしの allow → 🔴', () => {
    const r = analyzeServiceRules(ALL('allow read, write: if true;'), 'firestore', NOW);
    assert.deepEqual(r.findings.map((f) => [f.severity, f.reason, f.access, f.scope]), [['danger', 'open', 'read-write', 'all']]);
    assert.equal(r.findings[0]?.line, 5);
    assert.equal(analyzeServiceRules(ALL('allow read;'), 'firestore', NOW).findings[0]?.severity, 'danger');
    assert.equal(analyzeServiceRules(ALL('allow read: if true;'), 'firestore', NOW).findings[0]?.severity, 'danger');
    const storage = `rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /{allPaths=**} {\n      allow read, write: if true;\n    }\n  }\n}\n`;
    assert.deepEqual(analyzeServiceRules(storage, 'storage', NOW).findings.map((f) => [f.severity, f.scope]), [['danger', 'all']]);
  });

  it('positive：一部のパスでも、誰でも書き込める → 🔴。一部のパスを誰でも読める → 🟠（公開してよいデータか確認）', () => {
    const r = analyzeServiceRules(firestore('    match /posts/{id} {\n      allow read: if true;\n      allow create: if true;\n    }'), 'firestore', NOW);
    assert.deepEqual(r.findings.map((f) => [f.severity, f.access, f.path]), [
      ['warn', 'read', '/databases/{database}/documents/posts/{id}'],
      ['danger', 'write', '/databases/{database}/documents/posts/{id}'],
    ]);
  });

  it('期限付きのテストモード：期限前 → 🔴、期限切れ → 🟠', () => {
    assert.equal(analyzeServiceRules(ALL('allow read, write: if request.time < timestamp.date(2026, 11, 9);'), 'firestore', NOW).findings[0]?.reason, 'test-mode-active');
    assert.equal(analyzeServiceRules(ALL('allow read, write: if request.time < timestamp.date(2099, 1, 1);'), 'firestore', NOW).findings[0]?.severity, 'danger');
    const expired = analyzeServiceRules(ALL('allow read, write: if request.time < timestamp.date(2025, 1, 1);'), 'firestore', NOW).findings[0];
    assert.deepEqual([expired?.severity, expired?.reason], ['warn', 'test-mode-expired']);
  });

  it('ログインしていれば誰でも：全体なら 🟠、一部のパスなら数えない', () => {
    assert.deepEqual(analyzeServiceRules(ALL('allow read, write: if request.auth != null;'), 'firestore', NOW).findings.map((f) => [f.severity, f.reason]), [['warn', 'auth-only']]);
    assert.deepEqual(analyzeServiceRules(firestore('    match /chats/{id} {\n      allow read, write: if request.auth != null;\n    }'), 'firestore', NOW).findings, []);
  });

  it('safe / 判定しない：if false・本人だけ・関数を使う複雑なルール・コメントの中は数えない', () => {
    const safe = firestore(
      [
        '    // allow read, write: if true;',
        '    /* match /{document=**} { allow read, write: if true; } */',
        '    function isOwner(uid) { return request.auth != null && request.auth.uid == uid; }',
        '    match /users/{uid} {',
        '      allow read, write: if isOwner(uid);',
        '      allow delete: if false;',
        '    }',
        '    match /{document=**} {',
        '      allow read, write: if request.auth.uid == resource.data.owner && request.time < timestamp.date(2099, 1, 1);',
        '    }',
      ].join('\n'),
    );
    const r = analyzeServiceRules(safe, 'firestore', NOW);
    assert.equal(r.parsed, true);
    assert.deepEqual(r.findings, []);
  });

  it('Realtime Database：.read/.write が true → 🔴（全体）、一部のパスの読み取り → 🟠、テストモード、auth != null、コメント付き', () => {
    assert.deepEqual(analyzeDatabaseRules('{\n  "rules": {\n    ".read": true,\n    ".write": true\n  }\n}', NOW).findings.map((f) => [f.severity, f.access, f.scope, f.line]), [['danger', 'read-write', 'all', 3]]);
    assert.deepEqual(analyzeDatabaseRules('{"rules":{".read":"now < 1700000000000",".write":"now < 1700000000000"}}', NOW).findings.map((f) => [f.severity, f.reason]), [['warn', 'test-mode-expired']]);
    assert.deepEqual(analyzeDatabaseRules('{"rules":{".read":"now < 1900000000000",".write":"now < 1900000000000"}}', NOW).findings.map((f) => [f.severity, f.reason]), [['danger', 'test-mode-active']]);
    const mixed = '{\n  // 公開のお知らせ\n  "rules": {\n    "news": { ".read": true, ".write": false },\n    "users": { "$uid": { ".read": "$uid === auth.uid", ".write": "$uid === auth.uid" } }\n  }\n}';
    assert.deepEqual(analyzeDatabaseRules(mixed, NOW).findings.map((f) => [f.severity, f.path, f.access]), [['warn', '/news', 'read']]);
    assert.deepEqual(analyzeDatabaseRules('{"rules":{".read":"auth != null",".write":"auth != null"}}', NOW).findings.map((f) => f.reason), ['auth-only']);
    assert.deepEqual(analyzeDatabaseRules('{"rules":{".read":false,".write":false}}', NOW).findings, []);
    assert.equal(analyzeDatabaseRules('{ rules: broken', NOW).parsed, false);
  });

  it('画面：🔴・🟠 の項目に「このPC内のルールファイル」の注意書き。ルールファイルなしなら従来の案内。firebase.json で指定した名前も読む', () => {
    const root = project({ 'firebase.json': JSON.stringify({ firestore: { rules: 'rules/app.rules' } }), 'rules/app.rules': ALL('allow read, write: if true;'), 'database.rules.json': '{"rules":{"news":{".read":true}}}' });
    const list = checks(root);
    const danger = byId(list, 'firebase-rules-danger');
    assert.deepEqual(danger?.points, ['rules/app.rules:5（誰でもすべてのデータの読み取り・書き込みができる）']);
    assert.match(danger?.body ?? '', /このPC内のルールファイルを確認した結果です。現在公開中の設定そのものとは限りません/);
    assert.match(byId(list, 'firebase-rules-warn')?.body ?? '', /現在公開中の設定そのものとは限りません/);
    assert.equal(byId(list, 'firebase-rules')?.status, undefined);

    const safe = checks(project({ 'firebase.json': '{}', 'firestore.rules': ALL('allow read, write: if false;') }));
    assert.equal(byId(safe, 'firebase-rules-checked')?.status, 'ok');
    assert.match(byId(safe, 'firebase-rules-checked')?.body ?? '', /現在公開中の設定そのものとは限りません/);
    assert.deepEqual(dangerOrWarn(safe), []);

    const none = checks(project({ 'firebase.json': '{}' }));
    assert.equal(byId(none, 'firebase-rules')?.status, 'manual');

    const broken = checks(project({ 'database.rules.json': '{ not json' }));
    assert.equal(byId(broken, 'firebase-rules-unparsed')?.status, 'manual');
    assert.deepEqual(dangerOrWarn(broken), []);
  });
});

// ───────────── 2. 秘密鍵・サービスアカウント鍵 ─────────────

describe('2. 秘密鍵・サービスアカウント鍵', () => {
  it('中身で判定する：PKCS#8・PKCS#1・EC・OpenSSH・サービスアカウント → 本物の形。証明書・公開鍵 → 数えない', () => {
    for (const k of [KEYS.pkcs8, KEYS.pkcs1, KEYS.ec, KEYS.openssh]) assert.equal(findPrivateKey(k)?.value, 'real-like');
    assert.equal(findPrivateKey(KEYS.openssh)?.kind, 'openssh');
    assert.deepEqual([findPrivateKey(SERVICE_ACCOUNT)?.kind, findPrivateKey(SERVICE_ACCOUNT)?.value], ['service-account', 'real-like']);
    assert.equal(findPrivateKey(KEYS.encrypted)?.encrypted, true);
    assert.equal(findPrivateKey(CERT), undefined);
    assert.equal(findPrivateKey(KEYS.publicKey), undefined);
    // dummy：テスト用の語・鍵の形をしていない本体
    assert.equal(findPrivateKey(DUMMY_KEY)?.value, 'test-like');
    assert.equal(findPrivateKey(BROKEN_KEY)?.value, 'test-like');
    // JSON の type が service_account でも、private_key が鍵でなければ数えない
    assert.equal(findPrivateKey(JSON.stringify({ type: 'service_account', private_key: 'REPLACE_ME' })), undefined);
  });

  it('positive：Git で管理（tracked）・除外されていない（untracked）→ 🔴。拡張子に関係なく中身で判定', { skip: !hasGit && 'git がない' }, () => {
    const root = project(
      { 'keys/server.pem': KEYS.pkcs8, 'serviceAccountKey.json': SERVICE_ACCOUNT, 'notes/memo.txt': `サーバーの鍵\n${KEYS.pkcs1}`, 'deploy/id_ed25519': KEYS.openssh },
      { add: ['keys/server.pem'] },
    );
    const danger = byId(checks(root), 'private-key-danger');
    assert.equal(danger?.status, 'danger');
    assert.equal(danger?.points?.length, 4);
    assert.ok(danger?.points?.some((p) => p.startsWith('serviceAccountKey.json:') && p.includes('サービスアカウント鍵')));
    assert.ok(danger?.points?.some((p) => p.startsWith('keys/server.pem:1') && p.includes('Git で管理されている')));
    assertNoValues(root);
  });

  it('negative / safe：証明書・公開鍵の .pem、.gitignore 済みの鍵は 🔴・🟠 にしない（ignore 済みは補足だけ）', { skip: !hasGit && 'git がない' }, () => {
    const root = project({ '.gitignore': 'secrets/\n', 'certs/server.pem': CERT, 'certs/public.pem': KEYS.publicKey, 'secrets/key.pem': KEYS.pkcs8 }, { add: ['.gitignore', 'certs/server.pem', 'certs/public.pem'] });
    const list = checks(root);
    assert.deepEqual(dangerOrWarn(list), []);
    const info = byId(list, 'private-key-info');
    assert.deepEqual(info?.details?.map((d) => d.items), [['secrets/key.pem:1']]);
  });

  it('dummy：テスト用・形の崩れた鍵は Git で管理されていても数えない', { skip: !hasGit && 'git がない' }, () => {
    const list = checks(tracked({ 'test/fixtures/dummy.pem': DUMMY_KEY, 'test/fixtures/broken.key': BROKEN_KEY }));
    assert.deepEqual(dangerOrWarn(list), []);
    assert.equal(byId(list, 'private-key-info')?.details?.[0]?.items.length, 2);
  });

  it('Git なしのフォルダ・パスフレーズで暗号化された鍵 → 🟠', { skip: !hasGit && 'git がない' }, () => {
    assert.equal(byId(checks(project({ 'key.pem': KEYS.pkcs8 }, { git: 'none' })), 'private-key-warn')?.status, 'warn');
    const enc = checks(tracked({ 'key.pem': KEYS.encrypted }));
    assert.equal(byId(enc, 'private-key-danger'), undefined);
    assert.match(byId(enc, 'private-key-warn')?.points?.[0] ?? '', /パスフレーズで暗号化されている/);
  });

  it('GitHub App の秘密鍵（名前つきの定義）で見つけた場所は、秘密鍵の項目に重ねて出さない', { skip: !hasGit && 'git がない' }, () => {
    const pemEscaped = KEYS.pkcs1.replace(/\n/g, '\\n');
    const list = checks(tracked({ 'config/app.json': `{ "GITHUB_APP_PRIVATE_KEY": "${pemEscaped}" }` }));
    assert.ok(ids(list).includes('secret-github-app-private-key-danger'));
    assert.ok(!ids(list).includes('private-key-danger'));
  });
});

// ───────────── 3. 公開フォルダ ─────────────

const SQLITE = Buffer.concat([Buffer.from('SQLite format 3\0', 'latin1'), randomBytes(200)]);

describe('3. 公開フォルダ（public/・static/）', () => {
  it('positive：.env・秘密鍵・DB バックアップ・認証情報入り JSON・秘密の値は、Git の対象外でも 🔴', { skip: !hasGit && 'git がない' }, () => {
    const root = project(
      {
        '.gitignore': 'public/.env\npublic/backup/\npublic/keys/\nstatic/config.js\n',
        'public/.env': 'API_URL=https://api.example.jp\nDB_PASSWORD=hunter2hunter2\n',
        'public/backup/app.sqlite': SQLITE,
        'public/backup/dump.sql': '--\n-- PostgreSQL database dump\n--\nCREATE TABLE users (id int);\n',
        'public/keys/firebase-admin.json': SERVICE_ACCOUNT,
        'public/client_secret.json': JSON.stringify({ web: { client_id: '123.apps.googleusercontent.com', client_secret: OAUTH_SECRET } }),
        'static/config.js': `window.STRIPE = "${STRIPE.secret}";\n`,
      },
      { add: ['.gitignore'] },
    );
    const { list } = assertNoValues(root);
    const danger = byId(list, 'public-folder-danger');
    assert.equal(danger?.status, 'danger');
    const files = (danger?.points ?? []).map((p) => p.replace(/[:（].*$/, '')).sort();
    assert.deepEqual(files, ['public/.env', 'public/backup/app.sqlite', 'public/backup/dump.sql', 'public/client_secret.json', 'public/keys/firebase-admin.json']);
    // 公開フォルダの秘密鍵は、秘密鍵の項目には重ねない（Git の対象外でも、公開フォルダの項目で 🔴）
    assert.ok(!ids(list).includes('private-key-info') || !JSON.stringify(byId(list, 'private-key-info')).includes('firebase-admin'));
    // 既存の秘密情報の定義に一致する本物の値（Stripe）→ 🔴（Git の対象外でも）
    assert.match(byId(list, 'secret-stripe-danger')?.points?.[0] ?? '', /^static\/config\.js:1（.*公開フォルダ static\/ の中/);
  });

  it('negative：ふつうの .json・.txt・画像・見本の .env・CREATE TABLE だけの SQL は数えない', { skip: !hasGit && 'git がない' }, () => {
    const root = tracked({
      'public/manifest.json': JSON.stringify({ name: 'app', icons: [] }),
      'public/robots.txt': 'User-agent: *\nAllow: /\n',
      'public/data/prefectures.json': JSON.stringify([{ id: 1, name: '北海道' }]),
      'public/logo.png': randomBytes(64),
      'public/.env.example': 'API_URL=\nSTRIPE_SECRET_KEY=sk_live_your_key_here\n',
      'public/schema.sql': 'CREATE TABLE users (id int);\n',
      'public/.env': '# 空\n',
    });
    const list = checks(root);
    assert.deepEqual(dangerOrWarn(list).filter((c) => c.id.startsWith('public-folder') || c.id.startsWith('secret-')), []);
  });

  it('safe：公開してよいキー（Stripe の pk_・Firebase の apiKey）が公開フォルダにあっても数えない。テスト用の値も数えない', { skip: !hasGit && 'git がない' }, () => {
    const root = tracked({ 'public/app.js': `const pk = "${STRIPE.publishable}";\nconst firebaseConfig = { apiKey: "AIza${rand(35)}" };\nconst t = "${STRIPE.sandbox}";\n` });
    assert.deepEqual(dangerOrWarn(checks(root)), []);
  });

  it('データ入りの SQL（見出しなし）→ 🟠。firebase.json の Hosting の公開フォルダも対象', { skip: !hasGit && 'git がない' }, () => {
    const root = project({ 'firebase.json': JSON.stringify({ hosting: { public: 'web' } }), 'web/.env.production': 'SECRET_THING=abc\n', 'public/seed.sql': 'CREATE TABLE t (a int);\nINSERT INTO t VALUES (1);\n' });
    const list = checks(root);
    assert.deepEqual(byId(list, 'public-folder-danger')?.points, ['web/.env.production（.env ファイル（設定の値が入っている）・公開フォルダ web/ の中）']);
    assert.match(byId(list, 'public-folder-warn')?.points?.[0] ?? '', /^public\/seed\.sql（データ入りの SQL/);
  });
});

// ───────────── 4. Stripe・AWS ─────────────

const def = (id: string) => SECRET_DEFINITIONS.find((d) => d.id === id) ?? assert.fail(id);

describe('4. Stripe・AWS の秘密情報の定義', () => {
  it('Stripe：sk_live_・rk_live_ → 秘密。pk_ → 公開してよい。sk_test_・rk_test_ → テスト用。見本の値 → ダミー', () => {
    const stripe = def('stripe');
    assert.equal(classifySecretValue(stripe, STRIPE.secret).kind, 'real-like');
    assert.equal(classifySecretValue(stripe, STRIPE.restricted).kind, 'real-like');
    assert.equal(classifySecretValue(stripe, STRIPE.publishable).kind, 'public');
    assert.equal(classifySecretValue(stripe, `pk_test_${rand(99)}`).kind, 'public');
    assert.equal(classifySecretValue(stripe, STRIPE.sandbox).kind, 'test-like');
    assert.equal(classifySecretValue(stripe, `rk_test_${rand(99)}`).kind, 'test-like');
    assert.notEqual(classifySecretValue(stripe, 'sk_' + 'live_' + 'x'.repeat(24)).kind, 'real-like');
    assert.notEqual(classifySecretValue(stripe, 'sk_live_...').kind, 'real-like');
  });

  it('AWS：シークレットアクセスキー（40文字）→ 秘密。公式の見本の値・長さ違い・アクセスキー ID だけ → 数えない', () => {
    const aws = def('aws-secret-access-key');
    assert.equal(classifySecretValue(aws, AWS.secret).kind, 'real-like');
    assert.equal(classifySecretValue(aws, 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY').kind, 'test-like');
    assert.notEqual(classifySecretValue(aws, `${AWS.secret}A`).kind, 'real-like');
    assert.notEqual(classifySecretValue(aws, AWS.id).kind, 'real-like');
  });

  it('positive：Git で管理されたソース・設定・AWS の credentials ファイルへの直書き、公開用の変数 → 🔴（サービス名＋件数）', { skip: !hasGit && 'git がない' }, () => {
    const root = tracked({
      'src/pay.ts': `const stripe = new Stripe("${STRIPE.secret}");\nconst other = "${STRIPE.restricted}";\n`,
      'src/s3.ts': `new S3Client({ credentials: { accessKeyId: "${AWS.id}", secretAccessKey: "${AWS.secret}" } });\n`,
      '.aws/credentials': `[default]\naws_access_key_id = ${AWS.id}\naws_secret_access_key = ${AWS.secret}\n`,
      '.env.example': `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=${STRIPE.secret}\n`,
    });
    const { list } = assertNoValues(root);
    assert.match(byId(list, 'secret-stripe-danger')?.title ?? '', /^Stripe の秘密キー（シークレットキー・制限付きキー）が3か所/);
    assert.match(byId(list, 'secret-aws-secret-access-key-danger')?.title ?? '', /^AWS のシークレットアクセスキーが2か所/);
  });

  it('negative / safe：参照だけ・公開可能キー・テスト環境のキー・ignore 済みの .env・名前だけ似た変数は 🔴・🟠 にしない', { skip: !hasGit && 'git がない' }, () => {
    const root = project(
      {
        '.gitignore': '.env*\n',
        '.env.local': `STRIPE_SECRET_KEY=${STRIPE.secret}\nAWS_SECRET_ACCESS_KEY=${AWS.secret}\nAWS_ACCESS_KEY_ID=${AWS.id}\n`,
        'src/a.ts': [
          'const s = new Stripe(process.env.STRIPE_SECRET_KEY);',
          `const pk = "${STRIPE.publishable}";`,
          `const t = "${STRIPE.sandbox}";`,
          'const c = { secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY };',
          `const MY_SECRET = "${rand(40, 'b64std')}";`,
          `const accessKeyId = "${AWS.id}";`,
        ].join('\n'),
        '.github/workflows/deploy.yml': 'env:\n  AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}\n  STRIPE_SECRET_KEY: ${{ secrets.STRIPE_SECRET_KEY }}\n',
        'docs/setup.md': `AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n`,
      },
      { add: ['.gitignore', 'src/a.ts', '.github/workflows/deploy.yml', 'docs/setup.md'] },
    );
    const { list } = assertNoValues(root);
    assert.deepEqual(dangerOrWarn(list), []);
    const info = byId(list, 'secrets-info');
    assert.ok(info?.details?.some((d) => d.summary.startsWith('Stripe の秘密キー（シークレットキー・制限付きキー）：参照している場所')));
    assert.ok(info?.details?.some((d) => d.summary.startsWith('AWS のシークレットアクセスキー：参照している場所')));
  });

  it('値の形だけでは、AWS は探さない（接頭辞がないため）。Stripe の sk_live_・rk_live_ は名前がなくても探す', { skip: !hasGit && 'git がない' }, () => {
    const list = checks(tracked({ 'src/a.ts': `const k = "${STRIPE.secret}";\nconst a = "${AWS.secret}";\n` }));
    assert.deepEqual(dangerOrWarn(list).map((c) => c.id), ['secret-stripe-danger']);
  });
});
