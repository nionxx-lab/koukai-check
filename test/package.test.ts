// Phase 4: npm 配布物の監査。npm pack --dry-run で、公開されるファイルを確認する。

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const PKG_DIR = fileURLToPath(new URL('../..', import.meta.url));
const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')) as Record<string, unknown>;

/**
 * npm 本体（npm-cli.js）の場所。シェルを通さずに node で起動する。
 * Windows の npm は npm.cmd で、Node.js はセキュリティ上の理由で .cmd をシェルなしでは起動しないため（spawn npm ENOENT / EINVAL）。
 */
function npmCli(): string {
  const candidates = [
    process.env.npm_execpath, // npm run test で起動したとき
    join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js'), // Windows の公式インストーラー
    join(dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'), // Linux・macOS
  ];
  const found = candidates.find((p): p is string => !!p && /npm-cli\.js$/.test(p) && existsSync(p));
  if (!found) throw new Error('npm が見つかりません（npm-cli.js）');
  return found;
}

function packFiles(): string[] {
  const out = execFileSync(process.execPath, [npmCli(), 'pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: PKG_DIR, encoding: 'utf8', env: { ...process.env, npm_config_loglevel: 'silent' } });
  const parsed = JSON.parse(out) as { files: { path: string }[] }[];
  return (parsed[0]?.files ?? []).map((f) => f.path).sort();
}

describe('npm 配布物', { timeout: 60_000 }, () => {
  const files = packFiles();

  it('含まれるのは実行に必要なファイルと README / LICENSE / package.json だけ', () => {
    for (const f of files) {
      assert.ok(
        /^(package\.json|README\.md|LICENSE|samples\/security-advisors\.sample\.json|dist\/(app|checks|cli|detect|diagnostics|explanations|report|shared|supabase|types)\/[a-z-]+\.js)$/.test(f),
        `想定外のファイル: ${f}`,
      );
    }
    assert.ok(files.includes('dist/cli/index.js'));
    assert.ok(files.includes('README.md'));
    assert.ok(files.includes('LICENSE'));
  });

  it('秘密情報・開発用ファイルを含まない', () => {
    for (const f of files) {
      assert.doesNotMatch(f, /\.env|result\.json|\.log$|\.png$|\.jpe?g$|\.git|\.npmrc|test|fixture|docs\/|src\/|\.ts$|\.map$|tsconfig|dist-test|preview\.js|format\.js|\.DS_Store|\.vscode|\.idea/i, f);
    }
  });

  it('同梱ファイルの中身にトークンらしき文字列・テスト用の秘密文字列がない', () => {
    for (const f of files) {
      const content = readFileSync(new URL(`../../${f}`, import.meta.url), 'utf8');
      assert.doesNotMatch(content, /sbp_[A-Za-z0-9]{16,}|SUPER_SECRET|eyJhbGciOi/, f);
    }
  });

  it('同梱サンプルに本物らしいトークンやプロジェクトIDを含まない', () => {
    const sample = readFileSync(new URL('../../samples/security-advisors.sample.json', import.meta.url), 'utf8');
    assert.doesNotMatch(sample, /sbp_|eyJ[A-Za-z0-9_-]{10,}|service_role/);
  });

  it('実行時の依存パッケージは0個', () => {
    assert.equal(pkg.dependencies, undefined);
    assert.equal(pkg.optionalDependencies, undefined);
    assert.equal(pkg.peerDependencies, undefined);
    assert.equal(pkg.bundleDependencies ?? pkg.bundledDependencies, undefined);
  });

  it('package.json の公開用フィールド', () => {
    assert.equal(pkg.name, 'koukai-check');
    assert.match(String(pkg.version), /^\d+\.\d+\.\d+$/);
    assert.deepEqual(pkg.bin, { 'koukai-check': 'dist/cli/index.js' });
    assert.equal(pkg.license, 'PolyForm-Shield-1.0.0');
    assert.deepEqual(pkg.engines, { node: '>=22' });
    assert.ok(Array.isArray(pkg.files));
    assert.ok(pkg.repository);
    assert.ok(Array.isArray(pkg.keywords));
    // 利用者のインストール時に任意のコードを実行させない（prepack は作者が pack/publish するときだけ動く）
    const scripts = (pkg.scripts ?? {}) as Record<string, string>;
    for (const hook of ['preinstall', 'install', 'postinstall', 'prepare']) assert.equal(scripts[hook], undefined, hook);
    assert.equal(scripts.prepack, 'npm run build', '公開時に必ずビルドし直す（古い dist を配布しない）');
  });

  it('bin のファイルは Node で直接実行できる（shebang付き）', () => {
    const bin = readFileSync(new URL('../../dist/cli/index.js', import.meta.url), 'utf8');
    assert.match(bin, /^#!\/usr\/bin\/env node\n/);
  });
});
