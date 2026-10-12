// Phase 4.6: Windows 向け単一実行ファイル（Node.js SEA）のビルド処理のテスト。

import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { isStandaloneExe } from '../src/cli/standalone.js';

const SCRIPT = new URL('../../scripts/build-windows-exe.mjs', import.meta.url).href;
const SEA_LINUX = fileURLToPath(new URL('../../build/sea/koukai-check-linux-x64', import.meta.url));

interface BuildModule {
  bundleCjs(root: string, entry: string): { code: string; moduleCount: number };
  stripAuthenticode(buf: Buffer): { buf: Buffer; removed: boolean };
}
const load = async () => (await import(SCRIPT)) as BuildModule;

const roots: string[] = [];
after(() => roots.forEach((r) => rmSync(r, { recursive: true, force: true })));

function cjsFixture(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'kc-sea-'));
  roots.push(root);
  for (const [rel, content] of Object.entries(files)) {
    mkdirSync(join(root, rel, '..'), { recursive: true });
    writeFileSync(join(root, rel), content);
  }
  return root;
}

describe('SEA 用の1ファイル結合', () => {
  it('相対 require を内部参照に置き換え、node: の組み込みだけを残す', async () => {
    const { bundleCjs } = await load();
    const root = cjsFixture({
      'cli/index.js': '#!/usr/bin/env node\n"use strict";\nconst a = require("../lib/a.js");\nconst path = require("node:path");\nglobalThis.__result = a.value + path.sep;',
      'lib/a.js': '"use strict";\nconst b = require("./b.js");\nexports.value = "a" + b.value;',
      'lib/b.js': '"use strict";\nexports.value = "b";',
    });
    const { code, moduleCount } = bundleCjs(root, 'cli/index.js');
    assert.equal(moduleCount, 3);
    assert.doesNotMatch(code, /^#!/m, 'shebang を取り除く');
    assert.doesNotMatch(code, /require\("\.\.?\//);
    const sandbox: Record<string, unknown> = { require: (id: string) => (id === 'node:path' ? { sep: '/' } : assert.fail(id)) };
    sandbox.globalThis = sandbox;
    vm.runInNewContext(code, sandbox);
    assert.equal(sandbox.__result, 'ab/');
  });

  it('外部パッケージの require が紛れ込んでいたら失敗する（実行時の依存は0のはず）', async () => {
    const { bundleCjs } = await load();
    const root = cjsFixture({ 'cli/index.js': 'require("lodash");' });
    assert.throws(() => bundleCjs(root, 'cli/index.js'), /外部モジュールの require: lodash/);
  });

  it('実際のソースを CommonJS で出力して結合でき、外部依存がない', async () => {
    const { bundleCjs } = await load();
    const out = mkdtempSync(join(tmpdir(), 'kc-sea-cjs-'));
    roots.push(out);
    const pkgRoot = fileURLToPath(new URL('../..', import.meta.url));
    execFileSync(process.execPath, [join(pkgRoot, 'node_modules/typescript/bin/tsc'), '-p', join(pkgRoot, 'tsconfig.sea.json'), '--outDir', out]);
    const { code, moduleCount } = bundleCjs(out, 'cli/index.js');
    assert.ok(moduleCount > 30, String(moduleCount));
    assert.match(code, /チェックするアプリのフォルダを選ぶ/);
    assert.doesNotMatch(code, /import\.meta/);
  });
});

describe('Authenticode 署名の除去', () => {
  function fakePe(withCert: boolean): Buffer {
    const buf = Buffer.alloc(0x400 + (withCert ? 0x40 : 0));
    buf.write('MZ', 0, 'latin1');
    buf.writeUInt32LE(0x80, 0x3c);
    buf.write('PE\0\0', 0x80, 'latin1');
    const opt = 0x80 + 24;
    buf.writeUInt16LE(0x20b, opt); // PE32+
    buf.writeUInt32LE(0x1234, opt + 64); // CheckSum
    if (withCert) {
      buf.writeUInt32LE(0x400, opt + 112 + 32);
      buf.writeUInt32LE(0x40, opt + 112 + 36);
    }
    return buf;
  }

  it('末尾の証明書テーブルを取り除き、ディレクトリとチェックサムを0にする', async () => {
    const { stripAuthenticode } = await load();
    const { buf, removed } = stripAuthenticode(fakePe(true));
    assert.equal(removed, true);
    assert.equal(buf.length, 0x400);
    const opt = 0x80 + 24;
    assert.equal(buf.readUInt32LE(opt + 112 + 32), 0);
    assert.equal(buf.readUInt32LE(opt + 112 + 36), 0);
    assert.equal(buf.readUInt32LE(opt + 64), 0);
  });

  it('署名がなければそのまま、PE でなければ失敗する', async () => {
    const { stripAuthenticode } = await load();
    assert.equal(stripAuthenticode(fakePe(false)).removed, false);
    assert.throws(() => stripAuthenticode(Buffer.alloc(0x200)), /PE ファイルではありません/);
  });
});

describe('単一実行ファイルとしての起動', () => {
  it('通常の node で動かしているときは SEA と判定しない', () => {
    assert.equal(isStandaloneExe(), false);
  });

  it('SEA 版（Linux・動作確認用）が Node.js なしで画面を起動し、「終了する」で終了コード0', { skip: !existsSync(SEA_LINUX) && 'npm run build:win で生成されていない' }, async () => {
    const child = spawn(SEA_LINUX, ['--no-open'], { env: { PATH: '/usr/bin:/bin' }, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', (c: Buffer) => (out += c.toString()));
    const exited = new Promise<number | null>((r) => child.once('exit', (c) => r(c)));
    const url = await new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(out)), 15_000);
      child.stdout.on('data', () => {
        const m = out.match(/http:\/\/127\.0\.0\.1:\d+\/r\/[0-9a-f]{32}\//);
        if (m) {
          clearTimeout(timer);
          resolve(m[0]);
        }
      });
    });
    assert.doesNotMatch(out, /黒い画面/, 'コンソールの注意書きは出さない（Windows 版はウィンドウのアプリ）');
    const home = await (await fetch(url)).text();
    assert.match(home, /チェックするアプリのフォルダを選ぶ/);
    const csrf = home.match(/name="csrf" value="([0-9a-f]+)"/)?.[1] ?? '';
    await fetch(`${url}quit`, { method: 'POST', headers: { origin: new URL(url).origin, 'content-type': 'application/x-www-form-urlencoded' }, body: `csrf=${csrf}` });
    assert.equal(await exited, 0);
  });
});
