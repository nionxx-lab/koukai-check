// 秘密鍵の取り出し・分類・結果への統合を、実際のファイル・実際の Git リポジトリで確かめる。
// 鍵はテストのたびに Node で作る（本物の秘密情報は使わない・リポジトリに鍵を置かない）。値はアサーションのメッセージにも出さない。

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, describe, it } from 'node:test';
import { scanPage } from '../src/app/pages.js';
import { buildChecks, type CheckItem } from '../src/checks/build.js';
import { scanProject } from '../src/detect/scan.js';

const hasGit = (() => {
  try {
    execFileSync('git', ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();
const skip = !hasGit && 'git がない';
const GIT_ID = ['-c', 'user.name=koukai-check test', '-c', 'user.email=test@koukai-check.invalid', '-c', 'commit.gpgsign=false', '-c', 'core.autocrlf=false'];
const git = (cwd: string, ...args: string[]) => execFileSync('git', [...GIT_ID, ...args], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
const roots: string[] = [];
after(() => roots.forEach((r) => rmSync(r, { recursive: true, force: true })));

/** ファイルを書いたフォルダを作り、Git で管理する（tracked にする） */
function trackedProject(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'kc-keyint-'));
  roots.push(root);
  for (const [rel, content] of Object.entries({ 'package.json': '{"name":"app"}', ...files })) {
    const p = join(root, ...rel.split('/'));
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, content);
  }
  git(root, 'init', '-q');
  git(root, 'add', '-f', '-A');
  return root;
}

/** 本物の RSA 鍵の本体（base64・改行なし）。テストのたびに作る */
const realBody = () =>
  generateKeyPairSync('rsa', { modulusLength: 2048 })
    .privateKey.export({ type: 'pkcs8', format: 'pem' })
    .toString()
    .split('\n')
    .filter((l) => l && !l.startsWith('-----'))
    .join('');
const BEGIN = '-----BEGIN PRIVATE KEY-----';
const END = '-----END PRIVATE KEY-----';
// ソースコードに書かれる「\n」（バックスラッシュと n の2文字）
const NL = '\\n';
const pemFile = (body: string) => `${BEGIN}\n${body.match(/.{1,64}/g)?.join('\n')}\n${END}\n`;
const half = (body: string) => [body.slice(0, Math.floor(body.length / 2)), body.slice(Math.floor(body.length / 2))] as const;

/** 複数の行に分けて連結した、名前つきの鍵（レビューで指摘された書き方） */
function namedMultiline(body: string, name = 'GITHUB_APP_PRIVATE_KEY'): string {
  const [a, b] = half(body);
  return `export const ${name} =\n  "${BEGIN}${NL}" +\n  "${a}" +\n  "${b}" +\n  "${NL}${END}";\n`;
}

/** 同じファイルの定数から組み立てる鍵 */
function fromConstants(body: string, name = 'KEY'): string {
  const [a, b] = half(body);
  return `const PART1 = "${a}";\nconst PART2 = "${b}";\nexport const ${name} = "${BEGIN}${NL}" + PART1 + PART2 + "${NL}${END}";\n`;
}

const lineOf = (text: string, needle: string) => text.slice(0, text.indexOf(needle)).split('\n').length;

/** そのファイルを指す 🔴・🟠 の場所（カードの id と状態つき） */
function placesOf(list: CheckItem[], file: string): { id: string; status: CheckItem['status']; point: string }[] {
  return list
    .filter((c) => c.status === 'danger' || c.status === 'warn')
    .flatMap((c) => (c.points ?? []).filter((p) => p.startsWith(`${file}:`) || p.includes(` ${file}`) || p.includes(`${file}（`)).map((point) => ({ id: c.id, status: c.status, point })));
}

/** 結果（画面の文字列・修正の依頼文）とHTMLに、鍵の値の断片が含まれていないこと */
function assertNoKeyValue(list: CheckItem[], html: string, bodies: string[]): void {
  const text = JSON.stringify(list);
  for (const body of bodies) {
    for (let at = 0; at + 24 <= body.length; at += 97) {
      const part = body.slice(at, at + 24);
      assert.ok(!text.includes(part), '鍵の値が結果・依頼文に含まれていない');
      assert.ok(!html.includes(part), '鍵の値が HTML に含まれていない');
    }
  }
}

describe('秘密鍵：実際のファイル・Git で、検出が後の段階で消えない', () => {
  it('1. ふつうの PEM ファイル → 🔴', { skip }, () => {
    const root = trackedProject({ 'keys/app.pem': pemFile(realBody()) });
    const places = placesOf(buildChecks(scanProject(root)), 'keys/app.pem');
    assert.deepEqual(places.map((p) => [p.id, p.status]), [['private-key-danger', 'danger']]);
  });

  it('2. 同じ行で連結した PEM → 🔴', { skip }, () => {
    const [a, b] = half(realBody());
    const root = trackedProject({ 'src/key.ts': `export const KEY = "${BEGIN}${NL}" + "${a}" + "${b}" + "${NL}${END}";\n` });
    const places = placesOf(buildChecks(scanProject(root)), 'src/key.ts');
    assert.deepEqual(places.map((p) => [p.id, p.status]), [['private-key-danger', 'danger']]);
  });

  it('3. 複数の行で連結した名前つきの鍵（GITHUB_APP_PRIVATE_KEY）→ 🔴 が1件（消えない・重ならない）', { skip }, () => {
    const root = trackedProject({ 'src/github.ts': namedMultiline(realBody()) });
    const places = placesOf(buildChecks(scanProject(root)), 'src/github.ts');
    assert.equal(places.length, 1, places.map((p) => p.id).join(' / '));
    assert.equal(places[0]?.status, 'danger');
  });

  it('4. 同じファイルの定数から組み立てた鍵 → 🔴（名前つきでも、名前なしでも）', { skip }, () => {
    const root = trackedProject({ 'src/plain.ts': fromConstants(realBody()), 'src/named.ts': fromConstants(realBody(), 'GITHUB_APP_PRIVATE_KEY') });
    const list = buildChecks(scanProject(root));
    for (const file of ['src/plain.ts', 'src/named.ts']) {
      const places = placesOf(list, file);
      assert.equal(places.length, 1, `${file}: ${places.map((p) => p.id).join(' / ')}`);
      assert.equal(places[0]?.status, 'danger', file);
    }
  });

  it('5. 一部を復元できないが根拠が十分な鍵 → 少なくとも 🟠（「復元できない」と分かる）', { skip }, () => {
    const [a] = half(realBody());
    const root = trackedProject({
      'src/imported.ts': `import { PART2 } from './parts';\nconst PART1 = "${a}";\nexport const KEY = "${BEGIN}${NL}" + PART1 + PART2 + "${NL}${END}";\n`,
      'src/called.ts': `export const KEY = "${BEGIN}${NL}" + "${a}" + loadRest() + "${NL}${END}";\n`,
    });
    const list = buildChecks(scanProject(root));
    for (const file of ['src/imported.ts', 'src/called.ts']) {
      const places = placesOf(list, file);
      assert.equal(places.length, 1, `${file}: ${places.map((p) => p.id).join(' / ')}`);
      assert.ok(places[0]?.status === 'warn' || places[0]?.status === 'danger', file);
      assert.match(places[0]?.point ?? '', /復元できない/, file);
    }
  });

  it('6. 名前つきの判定が鍵を読めなくても、秘密鍵の項目の 🔴 は残る', { skip }, () => {
    const [a, b] = half(realBody());
    // 名前の直後が関数の呼び出しなので、名前つきの判定は鍵の式を読めない
    const code = `export const GITHUB_APP_PRIVATE_KEY = normalize(\n  "${BEGIN}${NL}" +\n  "${a}" +\n  "${b}" +\n  "${NL}${END}"\n);\n`;
    const root = trackedProject({ 'src/github.ts': code });
    const places = placesOf(buildChecks(scanProject(root)), 'src/github.ts');
    assert.ok(places.some((p) => p.id === 'private-key-danger' && p.point.startsWith(`src/github.ts:${lineOf(code, BEGIN)}`)), places.map((p) => p.id).join(' / '));
  });

  it('7. 1つのファイルに複数の鍵 → どれも消えず、重ならない', { skip }, () => {
    const named = namedMultiline(realBody());
    const [d1, d2] = half(realBody());
    const generic = `\nexport const DEPLOY_KEY = "${BEGIN}${NL}" + "${d1}" +\n  "${d2}" + "${NL}${END}";\n`;
    const fromParts = fromConstants(realBody(), 'SIGNING_KEY').replace(/PART/g, 'SIGN');
    const code = named + generic + fromParts;
    const root = trackedProject({ 'src/keys.ts': code, 'keys/two.pem': pemFile(realBody()) + pemFile(realBody()) });
    const list = buildChecks(scanProject(root));
    const places = placesOf(list, 'src/keys.ts');
    assert.equal(places.length, 3, places.map((p) => `${p.id}`).join(' / '));
    assert.ok(places.every((p) => p.status === 'danger'));
    assert.ok(places.some((p) => p.point.startsWith(`src/keys.ts:${lineOf(code, 'DEPLOY_KEY')}`)));
    assert.ok(places.some((p) => p.point.startsWith(`src/keys.ts:${lineOf(code, 'SIGNING_KEY')}`)));
    const pem = placesOf(list, 'keys/two.pem');
    assert.deepEqual(pem.map((p) => p.status), ['danger', 'danger'], '同じファイルの2つの PEM も、それぞれ数える');
  });

  it('8. コミットしてから消した鍵 → Git の履歴の項目に出る（名前つき・定数から組み立てた鍵・同じファイルの2つ目の鍵）', { skip }, () => {
    const root = trackedProject({ 'src/github.ts': namedMultiline(realBody()), 'src/parts.ts': fromConstants(realBody()) + fromConstants(realBody(), 'OTHER').replace(/PART/g, 'O') });
    git(root, 'commit', '-q', '-m', 'add keys');
    git(root, 'rm', '-q', '--', 'src/github.ts', 'src/parts.ts');
    git(root, 'commit', '-q', '-m', 'remove keys');
    const scan = scanProject(root);
    const list = buildChecks(scan);
    // リモートがないので、push 済みではなく 🟠（履歴の項目の決まり）
    const points = list.filter((c) => c.id === 'git-history-danger' || c.id === 'git-history-warn').flatMap((c) => c.points ?? []);
    assert.equal(points.filter((p) => p.includes('src/github.ts')).length, 1, '名前つきの鍵を1件として数える（消えない・重ならない）');
    assert.ok(points.some((p) => p.includes('src/parts.ts')));
    const keyFindings = scan.gitHistory.findings.filter((f) => f.kind === 'private-key' && f.file === 'src/parts.ts');
    assert.equal(keyFindings.length, 2, '同じファイルの2つの鍵を、それぞれ履歴に数える');
  });

  it('9. 公開フォルダの中の鍵 → 🔴 のまま（名前つき・連結・PEM ファイル）', { skip }, () => {
    const root = trackedProject({ 'public/config.js': namedMultiline(realBody()), 'public/app.pem': pemFile(realBody()), 'public/plain.js': fromConstants(realBody()) });
    const list = buildChecks(scanProject(root));
    const pub = list.find((c) => c.id === 'public-folder-danger')?.points ?? [];
    for (const file of ['public/config.js', 'public/app.pem', 'public/plain.js']) {
      assert.ok(pub.some((p) => p.includes(file)), `${file} が公開フォルダの 🔴 に出る`);
      assert.ok(!placesOf(list, file).some((p) => p.status === 'warn'), `${file} を 🟠 に下げない`);
    }
  });

  it('10. はっきりした見本・環境変数から読む鍵 → 🔴・🟠 にしない', { skip }, () => {
    const root = trackedProject({
      'src/sample.ts': `export const GITHUB_APP_PRIVATE_KEY =\n  "${BEGIN}${NL}" +\n  "YOUR_PRIVATE_KEY_HERE" +\n  "${NL}${END}";\n`,
      'src/dots.ts': `export const KEY = "${BEGIN}${NL}" + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC..." + "${NL}${END}";\n`,
      'src/env.ts': `export const KEY = "${BEGIN}${NL}" + process.env.KEY_BODY + "${NL}${END}";\n`,
      'src/envconst.ts': `const BODY = process.env.KEY_BODY;\nexport const GITHUB_APP_PRIVATE_KEY = "${BEGIN}${NL}" + BODY + "${NL}${END}";\n`,
    });
    const list = buildChecks(scanProject(root));
    for (const file of ['src/sample.ts', 'src/dots.ts', 'src/env.ts', 'src/envconst.ts']) {
      assert.deepEqual(placesOf(list, file).map((p) => p.id), [], file);
    }
  });

  it('12. 同じ行に、暗号化した鍵と名前つきの鍵 → それぞれ 🟠・🔴 で、消えず重ならない（現在のファイル・Git の履歴）', { skip }, () => {
    const encrypted = generateKeyPairSync('rsa', { modulusLength: 2048 })
      .privateKey.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: 'koukai-check-test' })
      .toString()
      .split('\n')
      .filter((l) => l && !l.startsWith('-----'))
      .join('');
    const code = `const A = "-----BEGIN ENCRYPTED PRIVATE KEY-----${NL}${encrypted}${NL}-----END ENCRYPTED PRIVATE KEY-----"; export const GITHUB_APP_PRIVATE_KEY = "${BEGIN}${NL}${realBody()}${NL}${END}";\n`;
    const root = trackedProject({ 'src/same-line.ts': code });
    const places = placesOf(buildChecks(scanProject(root)), 'src/same-line.ts');
    assert.deepEqual(places.map((p) => p.status).sort(), ['danger', 'warn'], places.map((p) => p.id).join(' / '));
    assert.ok(places.some((p) => p.id === 'private-key-warn' && p.point.includes('暗号化')), '暗号化した鍵は 🟠');
    assert.ok(places.some((p) => p.id === 'secret-github-app-private-key-danger'), '名前つきの鍵は 🔴');

    git(root, 'commit', '-q', '-m', 'add');
    git(root, 'rm', '-q', '--', 'src/same-line.ts');
    git(root, 'commit', '-q', '-m', 'remove');
    const findings = scanProject(root).gitHistory.findings.filter((f) => f.file === 'src/same-line.ts');
    assert.deepEqual(findings.map((f) => (f.kind === 'secret' ? f.defId : `key:${f.encrypted ? 'encrypted' : 'plain'}`)).sort(), ['github-app-private-key', 'key:encrypted']);
  });

  it('13. 同じファイルの定数を何段もたどる鍵 → ふつうの深さは 🔴、上限を超えても 🟠 以上（ダミー扱いしない）', { skip }, () => {
    /** P0 → P1 → … → P{depth}（鍵の本体） */
    const chain = (depth: number) => {
      const lines = [`const P${depth} = "${realBody()}";`];
      for (let i = depth - 1; i >= 0; i--) lines.push(`const P${i} = P${i + 1};`);
      return `${lines.join('\n')}\nexport const KEY = "${BEGIN}${NL}" + P0 + "${NL}${END}";\n`;
    };
    const root = trackedProject({ 'src/depth5.ts': chain(5), 'src/depth40.ts': chain(40) });
    const list = buildChecks(scanProject(root));
    assert.deepEqual(placesOf(list, 'src/depth5.ts').map((p) => p.status), ['danger'], 'P0 → … → P5');
    const deep = placesOf(list, 'src/depth40.ts');
    assert.equal(deep.length, 1, '上限を超える深さでも消えない');
    assert.match(deep[0]?.point ?? '', /復元できない/);
  });

  it('11. 鍵の値は、結果・AI への修正の依頼文・HTML に入らない', { skip }, () => {
    const bodies = [realBody(), realBody(), realBody(), realBody()];
    const [a] = half(bodies[3] ?? '');
    const root = trackedProject({
      'src/github.ts': namedMultiline(bodies[0] ?? ''),
      'src/parts.ts': fromConstants(bodies[1] ?? ''),
      'keys/app.pem': pemFile(bodies[2] ?? ''),
      'src/partial.ts': `export const KEY = "${BEGIN}${NL}" + "${a}" + loadRest() + "${NL}${END}";\n`,
    });
    const scan = scanProject(root);
    const list = buildChecks(scan);
    // 依頼文が組み立てられていること（中身の確認の前提）
    assert.ok(list.some((c) => c.status === 'danger' && c.guide), '🔴 の項目に直し方・依頼文がある');
    const html = scanPage({ base: '/r/x/', csrf: 'c', nonce: 'n', scan, checks: list });
    assertNoKeyValue(list, html, bodies);
    assert.ok(!JSON.stringify(scan).includes((bodies[0] ?? '').slice(200, 230)), '診断の結果（ScanResult）にも値を持たない');
  });
});
