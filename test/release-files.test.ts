// 公開リポジトリにそのまま置ける状態かを確かめる（公開用のファイル・ワークフロー・README・作者固有の情報）。

import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const read = (rel: string) => readFileSync(join(ROOT, rel), 'utf8');
const WORKFLOW = '.github/workflows/koukai-check-windows.yml';

/** 公開する（Git で管理する）テキストのファイル。生成物・依存パッケージ・exe は除く */
function publicTextFiles(): string[] {
  const skip = new Set(['node_modules', 'dist', 'dist-test', 'build', '.git']);
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      const st = statSync(p);
      if (st.isDirectory()) {
        if (!skip.has(name)) walk(p);
        continue;
      }
      const rel = relative(ROOT, p).split('\\').join('/');
      if (rel.startsWith('release/windows/') && rel !== 'release/windows/README-ja.txt') continue; // 生成物（.gitignore）
      if (/\.(ico|png|jpg|exe|dll|zip|nupkg)$/i.test(name)) continue;
      out.push(rel);
    }
  };
  walk(ROOT);
  return out;
}

describe('公開リポジトリに置くファイル', () => {
  it('README・LICENSE・SECURITY・PRIVACY・CONTRIBUTING・CHANGELOG・.gitattributes・ワークフローがある', () => {
    for (const f of ['README.md', 'LICENSE', 'SECURITY.md', 'PRIVACY.md', 'CONTRIBUTING.md', 'CHANGELOG.md', '.gitattributes', '.gitignore', WORKFLOW, 'release/windows/README-ja.txt']) {
      assert.ok(existsSync(join(ROOT, f)), f);
    }
    assert.match(read('.gitattributes'), /^\* text=auto eol=lf$/m);
  });

  it('ワークフロー：公開リポジトリでは APP_DIR が「.」。開発リポジトリの同じファイルとは APP_DIR と PR のパスの条件だけが違う', () => {
    const pub = read(WORKFLOW).replace(/\r\n/g, '\n');
    assert.match(pub, /^ {2}APP_DIR: '\.'$/m);
    assert.doesNotMatch(pub, /koukai-check\/(package|release|\*\*)/, '公開リポジトリのパスに koukai-check/ が残っている');
    // 非公開の開発リポジトリ（このフォルダの親）にも置いている場合だけ、ずれていないことを確かめる
    const devPath = join(ROOT, '..', WORKFLOW);
    if (existsSync(devPath)) {
      const dev = readFileSync(devPath, 'utf8').replace(/\r\n/g, '\n');
      const normalize = (s: string) =>
        s
          .replace(/^ {2}APP_DIR: .*$/m, '  APP_DIR: <app>')
          .replace(/^ {2}pull_request:\n {4}paths:\n(?: {6}- .*\n)+/m, '  pull_request:\n');
      assert.equal(normalize(dev), normalize(pub));
      assert.match(dev, /^ {2}APP_DIR: koukai-check$/m);
    }
  });

  it('package.json：公開リポジトリを指し、npm には公開しない（private）', () => {
    const pkg = JSON.parse(read('package.json')) as Record<string, unknown>;
    assert.equal(pkg.private, true);
    assert.deepEqual(pkg.repository, { type: 'git', url: 'git+https://github.com/nionxx-lab/koukai-check.git' });
    assert.match(String(pkg.homepage), /^https:\/\/github\.com\/nionxx-lab\/koukai-check/);
  });

  it('README：最初に何のツールかを書き、保証しないこと・Git がない場合・オフラインで使えることを明記。一般向けに npx を案内しない', () => {
    const readme = read('README.md');
    const head = readme.split('\n').slice(0, 5).join('\n');
    assert.match(head, /AI で作ったアプリを公開する前に、秘密情報や危険な公開設定を確認する Windows アプリ/);
    for (const re of [/完全な安全を保証するツールではありません/, /高度な脆弱性スキャナではありません/, /Git が入っていなくても使えます/, /Git の履歴のチェックだけを飛ばします/, /オフラインで使えます/, /作者のサーバー/, /テレメトリ/, /広告/, /アカウント登録/, /ファイルを書き換えません/]) {
      assert.match(readme, re);
    }
    assert.doesNotMatch(readme, /npx /);
  });

  it('PRIVACY：通信する場合・WebView2・作者のサーバーを使わないことを明記', () => {
    const privacy = read('PRIVACY.md');
    for (const re of [/このPCの中だけ/, /作者のサーバー自体を使っていません/, /テレメトリ/, /広告はありません/, /アカウント登録は不要/, /ファイルを書き換えません/, /api\.supabase\.com/, /既定のブラウザ/, /WebView2/, /Microsoft へ送る処理はありません/]) {
      assert.match(privacy, re);
    }
  });

  it('CHANGELOG に移行元のコミットを記録し、CONTRIBUTING に MVP の凍結を書いている', () => {
    assert.match(read('CHANGELOG.md'), /d1c65d6/);
    assert.match(read('CONTRIBUTING.md'), /MVP の診断機能は凍結中/);
  });

  it('作者固有の情報（ユーザー名を含むパス）を含めない', () => {
    // 見本として使ってよい名前（例のユーザー名・CI のランナー）。非公開の開発リポジトリ・作者の別プロジェクトの名前は、公開するファイルに書かないよう、公開前の監査で別に確かめる
    const allowedUsers = new Set(['あなた', '山田', 'a', 'RUNNER~1', 'runneradmin', 'u', 'user', 'me']);
    const problems: string[] = [];
    for (const f of publicTextFiles()) {
      const text = readFileSync(join(ROOT, f), 'utf8');
      for (const m of text.matchAll(/[A-Za-z]:\\{1,2}Users\\{1,2}([^\\\s"'`<>|)…]+)/g)) {
        if (!allowedUsers.has(m[1] ?? '')) problems.push(`${f}: Windows のユーザー名を含むパス`);
      }
      for (const m of text.matchAll(/\/(?:home|Users)\/([a-z][\w.-]*)/g)) {
        if (!allowedUsers.has(m[1] ?? '')) problems.push(`${f}: ユーザー名を含むパス`);
      }
    }
    assert.deepEqual(problems, []);
  });
});

describe('ライセンス（本体：PolyForm Shield 1.0.0・第三者のソフトウェア：それぞれのライセンス）', () => {
  it('LICENSE：Required Notice と、PolyForm Shield 1.0.0 の公式の本文（そのまま）', async () => {
    const { createHash } = await import('node:crypto');
    const text = read('LICENSE').replace(/\r\n/g, '\n');
    const [notice, blank, ...body] = text.split('\n');
    assert.equal(notice, 'Required Notice: Copyright (c) 2026 nionxx-lab (https://github.com/nionxx-lab)');
    assert.equal(blank, '');
    // 公式（polyformproject/polyform-licenses のタグ 1.0.0 の PolyForm-Shield-1.0.0.md）の SHA256
    assert.equal(createHash('sha256').update(body.join('\n')).digest('hex'), '56328093d57c87dcf2811ddcc824caf2723a07ffc332e6fbe4f9f108a2893a91');
  });

  it('本体のライセンスとして MIT を書いていない（package.json・README・exe の情報）。README は source-available と表現する', () => {
    const pkg = JSON.parse(read('package.json')) as Record<string, unknown>;
    assert.equal(pkg.license, 'PolyForm-Shield-1.0.0');
    const lock = JSON.parse(read('package-lock.json')) as { packages: Record<string, { license?: string }> };
    assert.equal(lock.packages['']?.license, 'PolyForm-Shield-1.0.0');
    const readme = read('README.md');
    assert.match(readme, /source-available/);
    assert.doesNotMatch(readme, /open[ -]?source/i);
    assert.match(readme, /PolyForm Shield License 1\.0\.0/);
    assert.doesNotMatch(readme, /PolyForm Strict|非営利/);
    assert.doesNotMatch(readme, /^MIT（/m);
    assert.match(read('native/windows-host/app.rc'), /"LegalCopyright", "Copyright \(c\) 2026 nionxx-lab\. PolyForm Shield License 1\.0\.0"/);
    const build = read('scripts/build-windows-exe.mjs');
    assert.match(build, /LegalCopyright: 'Copyright \(c\) 2026 nionxx-lab\. PolyForm Shield License 1\.0\.0\./);
    assert.doesNotMatch(build, /MIT License, koukai-check/);
    assert.match(read('release/windows/README-ja.txt'), /PolyForm Shield License 1\.0\.0/);
    // 通信の説明は実際の挙動（Supabase の診断を選び、確認後に実行したときだけ接続する）と一致させる
    assert.match(read('release/windows/README-ja.txt'), /Supabase の診断を選び、確認の画面で「接続して診断する」を押して実行した場合にだけ、\r?\n\s*Supabase 公式API（api\.supabase\.com）へ接続します/);
    // README.md / PRIVACY.md と同じ説明：ローカル診断は作者のサーバーへ送らない・WebView2 は Microsoft と通信しうる
    const releaseReadme = read('release/windows/README-ja.txt');
    assert.match(releaseReadme, /通常のローカル診断（フォルダのチェック）では、診断するアプリのソースコード・認証情報・\r?\n\s*診断結果を作者のサーバーへ送信しません/);
    assert.match(releaseReadme, /「Microsoft Edge WebView2」は、Windows の設定に従って\r?\n\s*Microsoft と通信することがあります/);
    assert.match(releaseReadme, /Microsoft へ送る処理はありません/);
    for (const doc of [releaseReadme, read('README.md'), read('PRIVACY.md')]) {
      assert.doesNotMatch(doc, /完全オフライン|外部通信は一切|一切通信しません/, '通信しないとは言い切らない');
    }
  });

  it('TRADEMARKS：名前・ロゴは許諾の対象外で、公式でないものは公式を名乗れない', () => {
    const tm = read('TRADEMARKS.md');
    for (const re of [/koukai-check/, /nionxx-lab/, /ロゴ/, /許諾の対象ではありません/, /公式版であると名乗ったり/]) assert.match(tm, re);
  });

  it('THIRD-PARTY-NOTICES：Node.js の LICENSE 全文・MinGW-w64 のランタイム・winpthreads・GCC Runtime Library Exception・WebView2（BSD-3-Clause）を含む。版が違えば作らない', async () => {
    const mod = (await import(new URL('../../scripts/build-windows-exe.mjs', import.meta.url).href)) as {
      THIRD_PARTY_LICENSES: Record<string, { version: string; file: string; sha256: string }>;
      readThirdPartyLicense(e: { version: string; file: string; sha256: string }): string;
      thirdPartyNotices(o: { nodeVersion: string; webview2License: Buffer; toolchain?: { gcc: string; mingw: string } }): string;
    };
    // 置いている文書の SHA256 が、ビルドスクリプトの値と一致する
    for (const e of Object.values(mod.THIRD_PARTY_LICENSES)) assert.ok(mod.readThirdPartyLicense(e).length > 1000, e.file);
    const webview2 = Buffer.from('Copyright (C) Microsoft Corporation. All rights reserved.\nRedistribution and use in source and binary forms ... (BSD-3-Clause test text)');
    const text = mod.thirdPartyNotices({ nodeVersion: 'v24.18.0', webview2License: webview2, toolchain: { gcc: '16.2.0', mingw: '14.0.0' } });
    assert.ok(text.includes(mod.readThirdPartyLicense(mod.THIRD_PARTY_LICENSES.node as never)), 'Node.js の LICENSE 全文');
    for (const re of [/Node\.js is licensed for use as follows/, /MinGW-w64 runtime licensing/, /GCC RUNTIME LIBRARY EXCEPTION/, /Version 3\.1, 31 March 2009/, /BSD-3-Clause test text/, /PolyForm Shield License 1\.0\.0/, /winpthreads/]) {
      assert.match(text, re);
    }
    assert.throws(() => mod.thirdPartyNotices({ nodeVersion: 'v24.19.0', webview2License: webview2 }), /ライセンス文書がありません/);
    assert.throws(() => mod.thirdPartyNotices({ nodeVersion: 'v24.18.0', webview2License: webview2, toolchain: { gcc: '15.1.0', mingw: '14.0.0' } }), /ライセンス文書の版/);
    assert.throws(() => mod.thirdPartyNotices({ nodeVersion: 'v24.18.0', webview2License: webview2, toolchain: { gcc: '16.2.0', mingw: '13.0.0' } }), /ライセンス文書の版/);
  });

  it('Supabase の診断結果の例（サンプル・テストのデータ）は、説明の英文を独自の文にしている（API の構造・lint の名前は残す）', () => {
    const sample = JSON.parse(read('samples/security-advisors.sample.json')) as { lints: Record<string, unknown>[] };
    assert.ok(sample.lints.length > 0);
    for (const l of sample.lints) {
      for (const key of ['name', 'title', 'level', 'facing', 'categories', 'description', 'detail', 'remediation', 'metadata', 'cache_key']) assert.ok(key in l, key);
    }
    for (const f of ['samples/security-advisors.sample.json', 'test/fixtures.ts', 'test/app.test.ts', 'test/diagnostics.test.ts', 'docs/phase1-tech-validation.md']) {
      const t = read(f);
      assert.doesNotMatch(t, /\bDetects (cases|views|functions|tables|public)\b|HaveIBeenPwned\.org|has not been enabled|RLS Disabled in Public|Security Definer View/, f);
    }
  });
});
