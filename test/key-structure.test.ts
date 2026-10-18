// 秘密鍵の判定（鍵の構造で判定する）のテスト。
// 鍵は、決まった種（シード）の疑似乱数から作る。実行のたびに結果が変わらない（本物の鍵・本物の秘密情報は使わない）。
// 鍵の本体に「test」「fake」などの並びが含まれても、構造が正しければ本物の鍵として数えることを確かめる。

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, describe, it } from 'node:test';
import { buildChecks, privateKeyRisk } from '../src/checks/build.js';
import { findPrivateKey } from '../src/detect/key-files.js';
import { classifyKeyBody } from '../src/detect/key-structure.js';
import { scanProject, type PrivateKeyLocation } from '../src/detect/scan.js';
import { SECRET_DEFINITIONS } from '../src/detect/secret-defs.js';
import { classifySecretValue } from '../src/detect/secret-names.js';

// ───────────── 決まった結果になる疑似乱数と、鍵の形の組み立て ─────────────

function prng(seed: number): (n: number) => Buffer {
  let a = seed >>> 0;
  return (n: number) => {
    const out = Buffer.alloc(n);
    for (let i = 0; i < n; i++) {
      a = (a + 0x6d2b79f5) >>> 0;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      out[i] = ((t ^ (t >>> 14)) >>> 0) & 0xff;
    }
    return out;
  };
}

function derLen(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
const tlv = (tag: number, content: Buffer) => Buffer.concat([Buffer.from([tag]), derLen(content.length), content]);
const RSA_OID = Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]);

/** PKCS#8 の形（SEQUENCE { INTEGER 0, SEQUENCE { OID, NULL }, OCTET STRING { … } }）。中身は疑似乱数 */
function pkcs8Like(rand: (n: number) => Buffer, size = 600): Buffer {
  return tlv(0x30, Buffer.concat([tlv(0x02, Buffer.from([0])), tlv(0x30, RSA_OID), tlv(0x04, rand(size))]));
}
/** PKCS#1・SEC1 の形（SEQUENCE { INTEGER, INTEGER/OCTET STRING, … }） */
function pkcs1Like(rand: (n: number) => Buffer): Buffer {
  const big = (n: number) => tlv(0x02, Buffer.concat([Buffer.from([0]), rand(n)]));
  return tlv(0x30, Buffer.concat([tlv(0x02, Buffer.from([0])), big(256), tlv(0x02, Buffer.from([1, 0, 1])), big(256), big(128), big(128)]));
}

/** base64 にしたとき、指定の語がちょうど現れるように中身を書き換える（3バイトの区切りに合わせる） */
function plantWords(der: Buffer, words: string[], from = 60): Buffer {
  const out = Buffer.from(der);
  let at = Math.ceil(from / 3) * 3;
  for (const w of words) {
    const bytes = Buffer.from(w, 'base64');
    bytes.copy(out, at);
    at += 30;
  }
  return out;
}

const pem = (label: string, der: Buffer) => `-----BEGIN ${label}PRIVATE KEY-----\n${der.toString('base64').match(/.{1,64}/g)?.join('\n')}\n-----END ${label}PRIVATE KEY-----\n`;
const pemBody = (body: string, label = '') => `-----BEGIN ${label}PRIVATE KEY-----\n${body.match(/.{1,64}/g)?.join('\n') ?? body}\n-----END ${label}PRIVATE KEY-----\n`;

/** OpenSSH の秘密鍵の形（openssh-key-v1）。暗号の名前・鍵の導出・鍵の数・公開鍵・秘密の部分 */
function opensshLike(rand: (n: number) => Buffer, cipher = 'none'): string {
  const str = (b: Buffer | string) => {
    const v = typeof b === 'string' ? Buffer.from(b, 'latin1') : b;
    const len = Buffer.alloc(4);
    len.writeUInt32BE(v.length);
    return Buffer.concat([len, v]);
  };
  const one = Buffer.alloc(4);
  one.writeUInt32BE(1);
  const pub = Buffer.concat([str('ssh-ed25519'), str(rand(32))]);
  const check = rand(4);
  const priv = Buffer.concat([check, check, str('ssh-ed25519'), str(rand(32)), str(rand(64)), str('comment'), Buffer.from([1, 2, 3])]);
  const blob = Buffer.concat([Buffer.from('openssh-key-v1\0', 'latin1'), str(cipher), str(cipher === 'none' ? 'none' : 'bcrypt'), str(cipher === 'none' ? '' : rand(24)), one, str(pub), str(priv)]);
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${blob.toString('base64').match(/.{1,70}/g)?.join('\n')}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

function crc24(bytes: Buffer): number {
  let crc = 0xb704ce;
  for (const b of bytes) {
    crc ^= b << 16;
    for (let i = 0; i < 8; i++) {
      crc <<= 1;
      if (crc & 0x1000000) crc ^= 0x1864cfb;
    }
  }
  return crc & 0xffffff;
}
function pgpLike(rand: (n: number) => Buffer, breakCrc = false): string {
  const body = Buffer.concat([Buffer.from([0xc5, 0xcd, 0x01]), rand(461)]); // 新しい形式のパケット・タグ 5（秘密鍵）
  const crc = Buffer.alloc(3);
  crc.writeUIntBE(crc24(body) ^ (breakCrc ? 1 : 0), 0, 3);
  return `-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n${body.toString('base64').match(/.{1,64}/g)?.join('\n')}\n=${crc.toString('base64')}\n-----END PGP PRIVATE KEY BLOCK-----\n`;
}

const WORDS = ['test', 'fake', 'mock', 'xxxx', 'TEST', 'Fake', 'dumm'];
const WORD_RE = /test|fake|dummy|mock|xxxx/i;

// ───────────── 1. 語が含まれても、構造が正しければ本物として数える ─────────────

describe('秘密鍵：鍵の本体の語では判定しない', () => {
  it('PKCS#8・PKCS#1 の形の鍵に test・fake・mock・xxxx が含まれていても、本物の鍵として数える', () => {
    const rand = prng(20261018);
    for (const [label, der] of [
      ['', plantWords(pkcs8Like(rand), WORDS)],
      ['RSA ', plantWords(pkcs1Like(rand), WORDS)],
      ['EC ', plantWords(pkcs1Like(rand), ['xxxx', 'test'])],
      ['ENCRYPTED ', plantWords(pkcs8Like(rand), ['fake', 'mock'])],
    ] as const) {
      const text = pem(label, der);
      assert.ok(WORD_RE.test(text), `${label}：語が本体に含まれている（テストの前提）`);
      const found = findPrivateKey(text);
      assert.equal(found?.value, 'real-like', `${label || 'PKCS#8'} は本物として数える`);
    }
  });

  it('決まった種から作った300個の鍵の形は、語が含まれるものも含め、すべて本物として数える（結果が実行のたびに変わらない）', () => {
    const rand = prng(42);
    let withWords = 0;
    for (let i = 0; i < 300; i++) {
      const der = i % 2 ? pkcs8Like(rand, 400 + (i % 50)) : pkcs1Like(rand);
      const body = der.toString('base64');
      if (WORD_RE.test(body)) withWords++;
      assert.equal(classifyKeyBody(i % 2 ? '' : 'RSA ', body).value, 'real-like', `${i} 個目`);
    }
    // 偶然の並びは、乱数の鍵にふつうに起こる（旧方式なら、これらを見逃していた）
    assert.ok(withWords > 0, `語を含む鍵が1つもない（${withWords}）`);
  });

  it('OpenSSH・PGP・PuTTY の形の鍵も、構造と中身で判定する。OpenSSH の暗号化は暗号の名前で分かる', () => {
    const rand = prng(7);
    const ssh = findPrivateKey(opensshLike(rand));
    assert.deepEqual([ssh?.kind, ssh?.value, ssh?.encrypted], ['openssh', 'real-like', false]);
    const sshEnc = findPrivateKey(opensshLike(rand, 'aes256-ctr'));
    assert.deepEqual([sshEnc?.value, sshEnc?.encrypted], ['real-like', true]);
    assert.equal(findPrivateKey(pgpLike(rand))?.value, 'real-like');
    const putty = `PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: key\nPublic-Lines: 2\n${rand(51).toString('base64').match(/.{1,64}/g)?.join('\n')}\nPrivate-Lines: 1\n${rand(36).toString('base64')}\nPrivate-MAC: ${rand(32).toString('hex')}\n`;
    assert.equal(findPrivateKey(putty)?.value, 'real-like');
  });
});

// ───────────── 2. はっきりしたダミーは数えない ─────────────

describe('秘密鍵：見本・ダミーは数えない（誤検出を増やさない）', () => {
  it('見本の文字・同じ値の繰り返し・短すぎるものは、ダミーとして数えない', () => {
    for (const [label, text] of [
      ['見本の文字', pemBody('YOUR_PRIVATE_KEY_HERE')],
      ['省略記号', pemBody('MIIEvQIBADANBgkqhkiG9w0BAQEFAASC...')],
      ['山かっこ', pemBody('<your private key>')],
      ['ゼロ埋め', pemBody('A'.repeat(400))],
      ['見本の語＋ゼロ埋め', pemBody(`MIIEvDUMMYKEYFORTESTSONLY${'A'.repeat(200)}`)],
      ['同じ並びの繰り返し', pemBody('QUJD'.repeat(80))],
      ['短すぎる', pemBody('MIIBOgIBAAJBAK')],
      ['OpenSSH の見本', '-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----\n'],
      ['PGP の見本', '-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n<key>\n-----END PGP PRIVATE KEY BLOCK-----\n'],
    ] as const) {
      assert.equal(findPrivateKey(text)?.value, 'test-like', label);
    }
  });
});

// ───────────── 3. 判断できないものは安全扱いしない ─────────────

describe('秘密鍵：本物か判断できないものは「確認をおすすめ」にする', () => {
  const rand = prng(99);
  const uncertain: [string, string][] = [
    ['鍵の構造ではないランダムな中身', pemBody(Buffer.concat([Buffer.from([0x41]), rand(900)]).toString('base64'))],
    ['途中で切れた鍵', pemBody(pkcs8Like(rand).subarray(0, 500).toString('base64'))],
    ['OpenSSH の見出しの後が崩れている', `-----BEGIN OPENSSH PRIVATE KEY-----\n${Buffer.concat([Buffer.from('openssh-key-v1\0', 'latin1'), rand(300)]).toString('base64')}\n-----END OPENSSH PRIVATE KEY-----\n`],
    ['PGP のチェックサムが合わない', pgpLike(rand, true)],
  ];

  it('構造が崩れているが中身がランダムなものは uncertain（ダミーとは扱わない）', () => {
    for (const [label, text] of uncertain) assert.equal(findPrivateKey(text)?.value, 'uncertain', label);
  });

  it('uncertain の鍵は、Git で管理されていても 🔴 ではなく 🟠。Git の対象外なら補足だけ', () => {
    const base: Omit<PrivateKeyLocation, 'git'> = { file: 'keys/a.pem', line: 1, kind: 'pem', value: 'uncertain', encrypted: false };
    assert.equal(privateKeyRisk({ ...base, git: 'tracked' }), 'warn');
    assert.equal(privateKeyRisk({ ...base, git: 'untracked' }), 'warn');
    assert.equal(privateKeyRisk({ ...base, git: 'no-git' }), 'warn');
    assert.equal(privateKeyRisk({ ...base, git: 'ignored' }), 'info');
    assert.equal(privateKeyRisk({ ...base, git: 'ignored', publicDir: 'public' }), 'warn', '公開フォルダの中も 🟠');
    assert.equal(privateKeyRisk({ ...base, value: 'real-like', git: 'tracked' }), 'danger');
    assert.equal(privateKeyRisk({ ...base, value: 'test-like', git: 'tracked' }), 'info');
  });

  it('名前つきの秘密情報（GitHub App の秘密鍵）も同じ判定：語を含む本物の形 → 本物、判断できない → uncertain、見本 → 数えない', () => {
    const def = SECRET_DEFINITIONS.find((d) => d.id === 'github-app-private-key');
    assert.ok(def);
    const asEnv = (text: string) => text.replace(/\n/g, '\\n');
    const real = classifySecretValue(def, asEnv(pem('RSA ', plantWords(pkcs1Like(prng(5)), WORDS))));
    assert.deepEqual([real.kind, real.reason], ['real-like', 'private-key']);
    const unsure = classifySecretValue(def, asEnv(uncertain[0]?.[1] ?? ''));
    assert.deepEqual([unsure.kind, unsure.reason], ['uncertain', 'key-unverified']);
    assert.notEqual(classifySecretValue(def, asEnv(pemBody('YOUR_PRIVATE_KEY_HERE', 'RSA '))).kind, 'real-like');
  });
});

// ───────────── 4. 実際のフォルダ・Git の履歴で ─────────────

const hasGit = (() => {
  try {
    execFileSync('git', ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();
const GIT_ID = ['-c', 'user.name=koukai-check test', '-c', 'user.email=test@koukai-check.invalid', '-c', 'commit.gpgsign=false', '-c', 'core.autocrlf=false'];
const git = (cwd: string, ...args: string[]) => execFileSync('git', [...GIT_ID, ...args], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
const roots: string[] = [];
after(() => roots.forEach((r) => rmSync(r, { recursive: true, force: true })));
function project(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'kc-keystruct-'));
  roots.push(root);
  for (const [rel, content] of Object.entries(files)) {
    const p = join(root, ...rel.split('/'));
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, content);
  }
  return root;
}

describe('秘密鍵：フォルダのチェック結果', () => {
  it('語を含む本物の形の鍵は 🔴、判断できない鍵は 🟠、見本は数えない（Git で管理されている場合）', { skip: !hasGit && 'git がない' }, () => {
    const rand = prng(1234567);
    const root = project({
      'package.json': '{"name":"app"}',
      'keys/real.pem': pem('', plantWords(pkcs8Like(rand), WORDS)),
      'keys/unsure.pem': pemBody(Buffer.concat([Buffer.from([0x41]), rand(900)]).toString('base64')),
      'keys/sample.pem': pemBody('YOUR_PRIVATE_KEY_HERE'),
    });
    git(root, 'init', '-q');
    git(root, 'add', '-f', '--', 'keys/real.pem', 'keys/unsure.pem', 'keys/sample.pem');
    const list = buildChecks(scanProject(root));
    const danger = list.find((c) => c.id === 'private-key-danger');
    const warn = list.find((c) => c.id === 'private-key-warn');
    assert.ok(danger?.points?.some((p) => p.startsWith('keys/real.pem')), '語を含む本物の形の鍵は 🔴');
    assert.ok(!danger?.points?.some((p) => p.startsWith('keys/unsure.pem')));
    assert.ok(warn?.points?.some((p) => p.startsWith('keys/unsure.pem') && p.includes('本物か確認できない')), '判断できない鍵は 🟠');
    for (const c of list.filter((x) => x.status === 'danger' || x.status === 'warn')) {
      assert.ok(!(c.points ?? []).some((p) => p.startsWith('keys/sample.pem')), `見本の鍵を ${c.id} に数えない`);
    }
    // 修正ガイドも付いている
    assert.ok(danger?.guide && warn?.guide);
  });

  it('Git の履歴に残った、語を含む本物の形の鍵・判断できない鍵も、履歴の項目に出す', { skip: !hasGit && 'git がない' }, () => {
    const rand = prng(777);
    const root = project({ 'package.json': '{"name":"app"}' });
    git(root, 'init', '-q');
    writeFileSync(join(root, 'real.pem'), pem('', plantWords(pkcs8Like(rand), WORDS)));
    writeFileSync(join(root, 'unsure.pem'), pemBody(Buffer.concat([Buffer.from([0x41]), rand(900)]).toString('base64')));
    git(root, 'add', '-A');
    git(root, 'commit', '-q', '-m', 'add keys');
    git(root, 'rm', '-q', '--', 'real.pem', 'unsure.pem');
    git(root, 'commit', '-q', '-m', 'remove keys');
    const list = buildChecks(scanProject(root));
    const history = list.filter((c) => c.id.startsWith('git-history-'));
    const points = history.flatMap((c) => c.points ?? []);
    assert.ok(points.some((p) => p.includes('real.pem')), points.join(' / '));
    assert.ok(points.some((p) => p.includes('unsure.pem') && p.includes('本物か判断できない')), points.join(' / '));
  });
});

// ───────────── 5. コードの中で、文字列を連結して書いた鍵 ─────────────
// 本物の鍵（Node で作る）を、同じ行・複数の行の文字列リテラルに分けて書く。値はアサーションのメッセージにも出さない。

/** 本物の鍵の本体（base64・改行なし） */
function realBody(type: 'ed25519' | 'rsa'): string {
  const key = type === 'ed25519' ? generateKeyPairSync('ed25519').privateKey : generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  return key.export({ type: 'pkcs8', format: 'pem' }).toString().split('\n').filter((l) => l && !l.startsWith('-----')).join('');
}
/** 本体に + を含む本物の鍵（含むまで作り直す。RSA の本体はほぼ必ず + を含む） */
function realBodyWithPlus(): string {
  for (;;) {
    const body = realBody('rsa');
    const at = body.indexOf('+', 100);
    if (at > 0 && at < body.length - 100) return body;
  }
}
/** 本体を n 個に分ける（分け目の位置は呼び出し側で指定できる） */
function split(body: string, cuts: number[]): string[] {
  const out: string[] = [];
  let from = 0;
  for (const c of [...cuts, body.length]) {
    out.push(body.slice(from, c));
    from = c;
  }
  return out;
}
const BEGIN = '-----BEGIN PRIVATE KEY-----';
const END = '-----END PRIVATE KEY-----';
// ソースコードに書かれる「\n」（バックスラッシュと n の2文字）
const NL = '\\n';
const sameLine = (parts: string[], q = '"', op = ' + ') => `export const KEY = ${q}${BEGIN}${NL}${q}${op}${parts.map((p) => `${q}${p}${q}`).join(op)}${op}${q}${NL}${END}${q};\n`;
const value = (text: string | undefined) => findPrivateKey(text ?? '')?.value;

describe('秘密鍵：コードの中で文字列を連結して書いた鍵', () => {
  it('本物の Ed25519（PKCS#8）の鍵を、同じ行で複数の断片に分けても 🔴 の対象（本物）になる', () => {
    const body = realBody('ed25519');
    assert.equal(value(sameLine(split(body, [20, 41]))), 'real-like');
    assert.equal(value(sameLine(split(body, [10, 30, 50]))), 'real-like');
  });

  it('本体に + を含む鍵：+ を壊さずに本物として数える。分け目が + の直後でも（連結の + と本体の + が並んでも）本物', () => {
    const body = realBodyWithPlus();
    const plus = body.indexOf('+', 100);
    assert.equal(value(sameLine([body])), 'real-like', '1つの文字列');
    assert.equal(value(sameLine(split(body, [plus + 1]))), 'real-like', '断片が + で終わる');
    assert.equal(value(sameLine(split(body, [plus]))), 'real-like', '断片が + で始まる');
    assert.equal(value(sameLine(split(body, [plus, plus + 1]))), 'real-like', '+ だけの断片');
    // 引用符の外にある PEM ファイルの + も壊さない（これまでどおり）
    assert.equal(value(`${BEGIN}\n${body.match(/.{1,64}/g)?.join('\n')}\n${END}\n`), 'real-like');
  });

  it('空白・改行・引用符・行末の書き方が違っても、同じ本体を取り出す', () => {
    const body = realBodyWithPlus();
    const parts = split(body, [300, 700, 1100]);
    const lines = body.match(/.{1,64}/g) ?? [];
    for (const [label, code] of [
      ['空白なし', sameLine(parts, '"', '+')],
      ['タブ', sameLine(parts, '"', '\t+\t')],
      ['シングルクォート', sameLine(parts, "'")],
      ['テンプレートリテラル', sameLine(parts, '`')],
      ['行末に +', `const KEY = "${BEGIN}${NL}" +\n  ${parts.map((p) => `"${p}"`).join(' +\n  ')} +\n  "${NL}${END}";\n`],
      ['行頭に +', `const KEY = "${BEGIN}${NL}"\n  + ${parts.map((p) => `"${p}"`).join('\n  + ')}\n  + "${NL}${END}";\n`],
      ['CRLF', `const KEY = "${BEGIN}${NL}" +\r\n  ${parts.map((p) => `"${p}"`).join(' +\r\n  ')} +\r\n  "${NL}${END}";\r\n`],
      ['1行ずつ \\n 付きの文字列', `const KEY =\n  "${BEGIN}${NL}" +\n${lines.map((l) => `  "${l}${NL}" +`).join('\n')}\n  "${END}";\n`],
      ['配列の join', `const KEY = ["${BEGIN}", ${lines.map((l) => `"${l}"`).join(', ')}, "${END}"].join("${NL}");\n`],
      ['JSON のエスケープ（\\/）', `{"key": "${BEGIN}${NL}${body.replace(/\//g, '\\/')}${NL}${END}${NL}"}\n`],
    ] as const) {
      assert.equal(value(code), 'real-like', label);
    }
  });

  it('鍵ではない連結した文字列は 🔴 にしない（見本・変数との連結・鍵の構造ではない中身）', () => {
    assert.equal(value(sameLine(['YOUR', '_PRIVATE', '_KEY'])), 'test-like', '見本の文字');
    assert.equal(value(`const KEY = "${BEGIN}${NL}" + process.env.KEY_BODY + "${NL}${END}";\n`), 'test-like', '変数との連結（中身はコードに書かれていない）');
    const notKey = Buffer.concat([Buffer.from([0x41]), prng(3)(900)]).toString('base64');
    assert.equal(value(sameLine(split(notKey, [400]))), 'uncertain', '鍵の構造ではない中身は「判断できない」のまま（🔴 にはしない）');
  });

  it('名前つきの秘密情報（GitHub App の秘密鍵）も同じ取り出し方をする', () => {
    const def = SECRET_DEFINITIONS.find((d) => d.id === 'github-app-private-key');
    assert.ok(def);
    const body = realBodyWithPlus();
    const plus = body.indexOf('+', 100);
    const code = sameLine(split(body, [plus + 1])).replace(/^export const KEY = /, '').replace(/;\n$/, '');
    assert.equal(classifySecretValue(def, code).kind, 'real-like');
  });

  it('Git で管理されたソースファイルに書いた、連結した本物の鍵は 🔴（公開フォルダの中も 🔴）', { skip: !hasGit && 'git がない' }, () => {
    const body = realBodyWithPlus();
    const plus = body.indexOf('+', 100);
    const code = sameLine(split(body, [plus + 1, 900]));
    const root = project({ 'package.json': '{"name":"app"}', 'src/keys.ts': code, 'public/keys.js': code });
    git(root, 'init', '-q');
    git(root, 'add', '-f', '--', 'src/keys.ts', 'public/keys.js');
    const list = buildChecks(scanProject(root));
    const danger = list.find((c) => c.id === 'private-key-danger');
    assert.ok(danger?.points?.some((p) => p.startsWith('src/keys.ts')), '連結した本物の鍵は 🔴');
    assert.ok(!list.find((c) => c.id === 'private-key-warn')?.points?.some((p) => p.startsWith('src/keys.ts')), '🟠 に下げない');
    assert.ok(list.find((c) => c.id === 'public-folder-danger')?.points?.some((p) => p.startsWith('public/keys.js')), '公開フォルダの中も 🔴');
    // 画面に出す文字列・依頼文に、鍵の値が入らない
    const text = JSON.stringify(list);
    for (const part of [body.slice(100, 140), body.slice(-40)]) assert.ok(!text.includes(part), '鍵の値が結果に含まれていない');
  });
});
