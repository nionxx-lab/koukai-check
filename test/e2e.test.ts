// Phase 4: トークン漏洩の E2E テスト。
// 実際の CLI プロセスを起動し、api.supabase.com への fetch だけをテスト用に差し替えて（test/helpers/mock-supabase-fetch.ts）、
// stdout / stderr / 配信HTML / 保存HTML / 作業ディレクトリ・HOME・一時ディレクトリにトークンが残らないことを確認する。
// 子プロセスにもネットワークガードを読み込み、想定外の外部通信があれば失敗させる。

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { spawnInterruptible, windowsBaseEnv } from './helpers/interruptible.js';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

const TOKEN_BODY = 'SUPER_SECRET_TEST_TOKEN_123456';
const SCOPED = `sbp_fc_${TOKEN_BODY}`;
const LEGACY = `sbp_${TOKEN_BODY}`;
const REF = 'abcdefghijklmnopqrst';

const BIN = fileURLToPath(new URL('../src/cli/index.js', import.meta.url));
const GUARD = fileURLToPath(new URL('./helpers/network-guard.js', import.meta.url));
const MOCK = fileURLToPath(new URL('./helpers/mock-supabase-fetch.js', import.meta.url));
// --import には URL を渡す（Windows の絶対パス C:\… は、URL のスキーム「c:」と読まれて失敗するため）
const GUARD_URL = pathToFileURL(GUARD).href;
const MOCK_URL = pathToFileURL(MOCK).href;
const FIXTURE = fileURLToPath(new URL('../../samples/security-advisors.sample.json', import.meta.url));

const roots: string[] = [];
after(() => {
  for (const r of roots) rmSync(r, { recursive: true, force: true });
});

function sandbox() {
  const root = mkdtempSync(join(tmpdir(), 'kc-e2e-'));
  roots.push(root);
  const dirs = { home: join(root, 'home'), tmp: join(root, 'tmp'), work: join(root, 'work') };
  for (const d of Object.values(dirs)) mkdirSync(d);
  return { root, ...dirs };
}

function listAll(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? [p, ...listAll(p)] : [p];
  });
}

interface RunResult {
  code: number | null;
  stdout: string;
  stderr: string;
  html?: string;
  saved?: string;
  createdFiles: string[];
}

async function runCliProcess(options: { args?: string[]; stdin?: string; env?: Record<string, string>; fetchReport?: boolean }): Promise<RunResult> {
  const box = sandbox();
  // Ctrl+C を送るのは、レポートを取りに行く場合だけ（それ以外は、仲立ちを使わずにそのまま起動する）
  const child = spawnInterruptible(process.execPath, ['--import', GUARD_URL, '--import', MOCK_URL, BIN, 'supabase', '--no-open', ...(options.args ?? [])], {
    interruptible: options.fetchReport === true,
    cwd: box.work,
    env: {
      PATH: process.env.PATH ?? '',
      HOME: box.home,
      USERPROFILE: box.home,
      TMPDIR: box.tmp,
      TEMP: box.tmp,
      TMP: box.tmp,
      XDG_CONFIG_HOME: join(box.home, '.config'),
      XDG_CACHE_HOME: join(box.home, '.cache'),
      KC_TEST_FIXTURE: FIXTURE,
      ...windowsBaseEnv(),
      ...options.env,
    },
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (c: Buffer) => (stdout += c.toString()));
  child.stderr.on('data', (c: Buffer) => (stderr += c.toString()));
  child.stdin.end(options.stdin ?? '');

  const exited = child.exited;
  let html: string | undefined;
  let saved: string | undefined;

  try {
    if (options.fetchReport) {
      // 起動にかかる時間は、子プロセスが起動してから測る（Windows の Ctrl+C の仲立ちの準備時間を含めない）
      await child.ready;
      const url = await new Promise<string>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`URLが表示されない\nstdout:${stdout}\nstderr:${stderr}`)), 15_000);
        const onData = () => {
          const m = stdout.match(/http:\/\/127\.0\.0\.1:\d+\/r\/[0-9a-f]{32}/);
          if (m) {
            clearTimeout(timer);
            resolve(m[0]);
          }
        };
        child.stdout.on('data', onData);
        onData();
        void exited.then(() => reject(new Error(`早く終了した\nstdout:${stdout}\nstderr:${stderr}`)));
      });
      html = await (await fetch(url)).text();
      saved = await (await fetch(`${url}?download=1`)).text();
      child.interrupt();
    }
    const code = await exited;
    return { code, stdout, stderr, html, saved, createdFiles: listAll(box.root).filter((p) => !Object.values(box).includes(p)) };
  } finally {
    // 失敗したときも、子プロセスを残さない（残るとテストのプロセスが終われない）
    child.kill();
  }
}

function assertNoToken(r: RunResult, label: string) {
  for (const [where, text] of [
    ['stdout', r.stdout],
    ['stderr', r.stderr],
    ['HTML', r.html ?? ''],
    ['保存HTML', r.saved ?? ''],
  ] as const) {
    assert.ok(!text.includes(TOKEN_BODY), `${label}: ${where} にトークンが含まれている`);
  }
  assert.deepEqual(r.createdFiles, [], `${label}: ファイルが作られている`);
  assert.doesNotMatch(r.stderr, /UNEXPECTED_NETWORK/, `${label}: 想定外の外部通信`);
}

describe('E2E: トークン漏洩監査', { timeout: 60_000 }, () => {
  it('対話入力のトークン → 診断 → レポート配信 → 保存 → Ctrl+C', async () => {
    const r = await runCliProcess({ stdin: `${REF}\n${SCOPED}\n`, fetchReport: true });
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.stderr, new RegExp(`MOCK_REQUEST /v1/projects/${REF}/advisors/security auth_len=${'Bearer '.length + SCOPED.length} auth_tail_ok=true`), 'トークンは Supabase へは正しく送られている');
    assert.match(r.html ?? '', /修正してから公開することをおすすめします/);
    assert.equal(r.saved, r.html);
    assert.match(r.stdout, /終了しました/);
    assertNoToken(r, '対話入力');
  });

  it('環境変数の Legacy トークン（デバッグ表示オン）でも残らない', async () => {
    const r = await runCliProcess({ stdin: `${REF}\n`, env: { SUPABASE_ACCESS_TOKEN: LEGACY, KOUKAI_CHECK_DEBUG: '1' }, fetchReport: true });
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.stdout, /このトークンは広い権限を持っています/);
    assert.match(r.html ?? '', /このトークンは広い権限を持っています/);
    assertNoToken(r, '環境変数');
  });

  it('無効なトークン（401）・権限不足（403）・利用制限（429）・障害（500）のエラー表示に残らない', async () => {
    for (const status of ['401', '403', '429', '500']) {
      const r = await runCliProcess({ stdin: `${REF}\n`, env: { SUPABASE_ACCESS_TOKEN: SCOPED, KC_TEST_STATUS: status, KOUKAI_CHECK_DEBUG: '1' } });
      assert.equal(r.code, 1, `${status}: ${r.stderr}`);
      assert.doesNotMatch(r.stderr + r.stdout, /\n\s+at .+:\d+:\d+/, `${status}: スタックトレースが表示されている`);
      assertNoToken(r, `HTTP ${status}`);
    }
  });

  it('接続エラーのデバッグ表示にも残らない', async () => {
    const r = await runCliProcess({ stdin: `${REF}\n`, env: { SUPABASE_ACCESS_TOKEN: SCOPED, KC_TEST_NETWORK_ERROR: '1', KOUKAI_CHECK_DEBUG: '1' } });
    assert.equal(r.code, 1);
    assert.match(r.stdout, /Supabaseに接続できませんでした/);
    assertNoToken(r, '接続エラー');
  });

  it('入力途中で終わった場合（Ctrl+D 相当）も残らない', async () => {
    const r = await runCliProcess({ stdin: `${REF}\n` });
    assert.notEqual(r.code, 0);
    assertNoToken(r, '入力中断');
  });

  it('コマンド引数のトークンは拒否し、表示もしない', async () => {
    const r = await runCliProcess({ args: ['--token', SCOPED] });
    assert.equal(r.code, 2);
    assert.match(r.stderr, /コマンドに直接書く方法には対応していません/);
    assertNoToken(r, '--token');
  });
});

describe('E2E: 通信先監査', { timeout: 30_000 }, () => {
  it('診断1回で発生する外部通信は api.supabase.com への1回だけ', async () => {
    const r = await runCliProcess({ stdin: `${REF}\n${SCOPED}\n`, fetchReport: true });
    const requests = r.stderr.match(/MOCK_REQUEST [^\n]+/g) ?? [];
    assert.equal(requests.length, 1, r.stderr);
    assert.doesNotMatch(r.stderr, /UNEXPECTED_NETWORK/);
  });
});

describe('保存HTMLの内容', () => {
  it('保存HTMLは配信HTMLと同一で、注意書きとCSPを含む', async () => {
    const r = await runCliProcess({ stdin: `${REF}\n${SCOPED}\n`, fetchReport: true });
    assert.ok(r.saved);
    assert.match(r.saved, /保存したHTMLには診断結果やテーブル名などが含まれます。共有する場合は内容を確認してください。/);
    assert.match(r.saved, /<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;/);
    assert.doesNotMatch(r.saved, /https?:\/\/(?!supabase\.com\/)[^"\s<]+/, '外部URL（公式解説以外）を含まない');
    void readFileSync;
  });
});

describe('E2E: 一般ユーザー向けの画面（フォルダ選択）', { timeout: 30_000 }, () => {
  it('引数なしで画面のURLを表示し、「終了する」で終了コード0で終わる。外部通信もファイル作成もない', async () => {
    const box = sandbox();
    const child = spawn(process.execPath, ['--import', GUARD_URL, BIN, '--no-open'], {
      cwd: box.work,
      env: { PATH: process.env.PATH ?? '', HOME: box.home, USERPROFILE: box.home, TMPDIR: box.tmp, TEMP: box.tmp, TMP: box.tmp, ...windowsBaseEnv() },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c: Buffer) => (stdout += c.toString()));
    child.stderr.on('data', (c: Buffer) => (stderr += c.toString()));
    const exited = new Promise<number | null>((resolve) => child.once('exit', (code) => resolve(code)));
    const url = await new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(stdout + stderr)), 15_000);
      child.stdout.on('data', () => {
        const m = stdout.match(/http:\/\/127\.0\.0\.1:\d+\/r\/[0-9a-f]{32}\//);
        if (m) {
          clearTimeout(timer);
          resolve(m[0]);
        }
      });
    });
    const home = await (await fetch(url)).text();
    assert.match(home, /チェックするアプリのフォルダを選ぶ/);
    const csrf = home.match(/name="csrf" value="([0-9a-f]+)"/)?.[1] ?? '';
    const origin = new URL(url).origin;
    const quit = await fetch(`${url}quit`, { method: 'POST', headers: { origin, 'content-type': 'application/x-www-form-urlencoded' }, body: `csrf=${csrf}` });
    assert.equal(quit.status, 200);
    assert.equal(await exited, 0);
    assert.match(stdout, /終了しました/);
    assert.doesNotMatch(stderr, /UNEXPECTED_NETWORK/);
    assert.deepEqual(listAll(box.root).filter((p) => ![box.home, box.tmp, box.work].includes(p)), []);
  });
});
