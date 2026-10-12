// 技術の判定（フォルダの走査）の不具合の再現と、直したことの確認。
// 再現ケース：Windows 実機で `C:\Users\あなた\デスクトップ\projects\sample-app`（直下に package.json がある
// アプリのルート）を選んだのに、「使っている技術を判定できませんでした」「package.json が入っているフォルダを選び直してください」
// 「フォルダが大きいため、一部だけを調べました」と表示された。

import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { noTechMessage, scanPage } from '../src/app/pages.js';
import { buildChecks } from '../src/checks/build.js';
import { DEFAULT_LIMITS, scanProject } from '../src/detect/scan.js';

const BOM = '\uFEFF';
const REF = 'abcdefghijklmnopqrst';
const roots: string[] = [];
after(() => roots.forEach((r) => rmSync(r, { recursive: true, force: true })));

/** 日本語を含む親フォルダの下に、sample-app を作る */
function appRoot(): string {
  const base = mkdtempSync(join(tmpdir(), 'kc-scan-'));
  roots.push(base);
  const root = join(base, 'デスクトップ', 'projects', 'tools', 'sample-app');
  mkdirSync(root, { recursive: true });
  return root;
}

function write(root: string, rel: string, content: string): void {
  const path = join(root, ...rel.split('/'));
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, content);
}

function pkgJson(deps: Record<string, string>): string {
  return JSON.stringify({ name: 'sample-app', private: true, dependencies: deps }, null, 2);
}

describe('再現ケース：sample-app（Windows 実機で判定できなかったフォルダ）', () => {
  it('BOM 付きの package.json・.env と、件数・深さの上限を超える大きなフォルダでも、直下から判定できる', () => {
    const root = appRoot();
    // Windows の PowerShell 5.1（Out-File / Set-Content -Encoding utf8）やメモ帳は、先頭に BOM を付けることがある
    write(root, 'package.json', BOM + pkgJson({ next: '15.0.0', react: '19.0.0', '@supabase/supabase-js': '2.45.0' }));
    write(root, '.env.local', `${BOM}NEXT_PUBLIC_SUPABASE_URL=https://${REF}.supabase.co\nNEXT_PUBLIC_SUPABASE_ANON_KEY=x\n`);
    write(root, 'next.config.mjs', 'export default {};\n');
    // 件数の上限（20,000）を超えるファイル（例：書き出したデータやログ）。名前順で package.json より前に来る
    for (let i = 0; i < DEFAULT_LIMITS.maxEntries + 100; i++) write(root, `data/log-${String(i).padStart(5, '0')}.txt`, '');
    // 深さの上限（4）を超えるフォルダ
    write(root, 'src/app/(dashboard)/settings/profile/components/Form.tsx', 'export {};\n');

    const scan = scanProject(root);
    assert.equal(scan.rootPackageJson, 'found');
    assert.deepEqual(scan.techs.map((t) => t.id), ['supabase', 'nextjs', 'env']);
    assert.deepEqual(scan.supabaseRefs, [REF]);
    assert.ok(scan.techs.find((t) => t.id === 'nextjs')?.evidence.includes('package.json: next'));
    // BOM が変数名に混ざっていない
    assert.ok(scan.techs.find((t) => t.id === 'supabase')?.evidence.includes('.env.local: NEXT_PUBLIC_SUPABASE_URL'));
    assert.equal(scan.stats.truncated, true, '件数の上限は今までどおり');
    assert.equal(scan.rootName, 'sample-app');

    const html = scanPage({ base: '/r/x/', csrf: 'c', nonce: 'n', scan, checks: buildChecks(scan) });
    assert.doesNotMatch(html, /判定できませんでした|選び直してください/);
    assert.match(html, /Supabase のチェックを始める/);
    assert.match(html, /直下にある package\.json・\.env・設定ファイルは、すべて確認済み/);
  });

  it('直下の項目だけで件数の上限を超えていても、package.json・.env・設定ファイルは必ず確認する', () => {
    const root = appRoot();
    for (let i = 0; i < 50; i++) write(root, `a${String(i).padStart(2, '0')}.png`, '');
    write(root, 'package.json', pkgJson({ expo: '51.0.0' }));
    write(root, '.env', 'EXPO_PUBLIC_SUPABASE_URL=https://abcdefghijklmnopqrst.supabase.co\n');
    write(root, 'firebase.json', '{}');
    write(root, 'supabase/config.toml', 'project_id = "x"\n');
    const scan = scanProject(root, { maxDepth: 4, maxEntries: 5, maxFileBytes: DEFAULT_LIMITS.maxFileBytes });
    assert.equal(scan.stats.truncated, true);
    assert.deepEqual(scan.techs.map((t) => t.id), ['supabase', 'firebase', 'expo', 'env']);
    assert.ok(scan.techs.find((t) => t.id === 'supabase')?.evidence.includes('supabase/config.toml'));
    assert.equal(scan.envFiles.length, 1, '.env は1回だけ数える');
  });

  it('深さの上限に当たっただけでは「一部だけを調べました」と出さない', () => {
    const root = appRoot();
    write(root, 'package.json', pkgJson({ next: '15.0.0' }));
    write(root, 'src/a/b/c/d/e/f.ts', '');
    const scan = scanProject(root);
    assert.equal(scan.stats.truncated, false);
    assert.equal(scan.stats.depthLimited, true);
    const html = scanPage({ base: '/r/x/', csrf: 'c', nonce: 'n', scan, checks: buildChecks(scan) });
    assert.doesNotMatch(html, /一部だけを調べました/);
  });
});

describe('判定できなかったときの説明', () => {
  it('package.json はあるが対応する技術がない場合は、選び直しを求めない', () => {
    const root = appRoot();
    write(root, 'package.json', pkgJson({ vite: '5.0.0', react: '19.0.0' }));
    const scan = scanProject(root);
    assert.equal(scan.rootPackageJson, 'found');
    assert.deepEqual(scan.techs, []);
    assert.match(noTechMessage(scan), /package\.json は見つかりましたが、このツールがチェックに対応している技術/);
    assert.doesNotMatch(noTechMessage(scan), /選び直して/);
  });

  it('package.json が壊れている場合は、読み取れなかったと伝える', () => {
    const root = appRoot();
    write(root, 'package.json', '{ "dependencies": { "next": "15" }, }');
    const scan = scanProject(root);
    assert.equal(scan.rootPackageJson, 'invalid');
    assert.match(noTechMessage(scan), /中身を読み取れませんでした/);
  });

  it('直下に package.json がない場合だけ、選び直しを案内する', () => {
    const root = appRoot();
    write(root, 'README.md', '# x');
    const scan = scanProject(root);
    assert.equal(scan.rootPackageJson, 'missing');
    assert.match(noTechMessage(scan), /選び直してください/);
  });
});

describe('除外のルールは今までどおり', () => {
  it('node_modules の中の package.json は見ない', () => {
    const root = appRoot();
    write(root, 'package.json', pkgJson({}));
    write(root, 'node_modules/firebase/package.json', pkgJson({ firebase: '10' }));
    assert.deepEqual(scanProject(root).techs, []);
  });

  it('直下の supabase フォルダがリンクなら、たどらない（Windows ではジャンクション。権限なしで作れる）', () => {
    const outside = appRoot();
    write(outside, 'supabase/config.toml', 'x');
    const root = appRoot();
    write(root, 'package.json', pkgJson({}));
    symlinkSync(join(outside, 'supabase'), join(root, 'supabase'), process.platform === 'win32' ? 'junction' : 'dir');
    const scan = scanProject(root);
    assert.deepEqual(scan.techs, []);
  });

  // ファイルのシンボリックリンクは、Windows では開発者モードか管理者の権限がないと作れない（作れない環境では、利用者のフォルダにも存在しえない）
  const fileLinks = (() => {
    const dir = appRoot();
    write(dir, 'a.txt', 'x');
    try {
      symlinkSync(join(dir, 'a.txt'), join(dir, 'b.txt'), 'file');
      return true;
    } catch {
      return false;
    }
  })();
  it('直下の package.json・.env がシンボリックリンクなら、たどらない', { skip: !fileLinks && 'この環境ではファイルのシンボリックリンクを作れない（Windows の開発者モード・管理者権限なし）' }, () => {
    const outside = appRoot();
    write(outside, 'package.json', pkgJson({ next: '15.0.0' }));
    write(outside, '.env', 'SUPABASE_URL=x\n');
    const root = appRoot();
    symlinkSync(join(outside, 'package.json'), join(root, 'package.json'), 'file');
    symlinkSync(join(outside, '.env'), join(root, '.env'), 'file');
    const scan = scanProject(root);
    assert.equal(scan.rootPackageJson, 'missing');
    assert.deepEqual(scan.techs, []);
    assert.deepEqual(scan.envFiles, []);
  });
});
