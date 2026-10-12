import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { spawnInterruptible } from './helpers/interruptible.js';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { parseArgs, runCli, type CliDeps } from '../src/cli/app.js';
import type { ReportServer, StartOptions } from '../src/report/server.js';
import { SupabaseApiError, type SupabaseErrorKind } from '../src/supabase/errors.js';
import type { SecurityAdvisorResult } from '../src/types/advisor.js';
import { normalizeSecurityAdvisors } from '../src/supabase/normalize.js';

const REF = 'abcdefghijklmnopqrst';
const SAMPLE_PATH = fileURLToPath(new URL('../../samples/security-advisors.sample.json', import.meta.url));
const SAMPLE_RESULT = normalizeSecurityAdvisors(JSON.parse(readFileSync(SAMPLE_PATH, 'utf8'))) as SecurityAdvisorResult;

interface Harness {
  deps: CliDeps;
  out: string[];
  err: string[];
  asked: string[];
  secretAsked: number;
  tokensUsed: string[];
  refsUsed: string[];
  servedHtml?: string;
  opened: string[];
}

function harness(options: {
  argv?: string[];
  env?: Record<string, string>;
  answers?: string[];
  secrets?: string[];
  /** getSecurityAdvisors の応答を順に返す（エラー種別ならその例外を投げる） */
  responses?: (SecurityAdvisorResult | SupabaseErrorKind)[];
  openOk?: boolean;
}): Harness {
  const answers = [...(options.answers ?? [])];
  const secrets = [...(options.secrets ?? [])];
  const responses = [...(options.responses ?? [SAMPLE_RESULT])];
  const h: Harness = { out: [], err: [], asked: [], secretAsked: 0, tokensUsed: [], refsUsed: [], opened: [], deps: undefined as unknown as CliDeps };
  h.deps = {
    argv: options.argv ?? [],
    env: options.env ?? {},
    print: (m) => h.out.push(m),
    printError: (m) => h.err.push(m),
    ask: async (q) => {
      h.asked.push(q);
      const a = answers.shift();
      if (a === undefined) throw new Error('no more answers');
      return a;
    },
    askSecret: async () => {
      h.secretAsked++;
      const s = secrets.shift();
      if (s === undefined) throw new Error('no more secrets');
      return s;
    },
    createClient: (token) => ({
      getSecurityAdvisors: async (ref: string) => {
        h.tokensUsed.push(token);
        h.refsUsed.push(ref);
        const r = responses.shift() ?? SAMPLE_RESULT;
        if (typeof r === 'string') throw new SupabaseApiError(r, '/v1/x', 'mock');
        return r;
      },
    }),
    startServer: async (o: StartOptions): Promise<ReportServer> => {
      h.servedHtml = o.html;
      return { url: `http://127.0.0.1:5555/r/${'a'.repeat(32)}`, port: 5555, close: async () => undefined };
    },
    createNonce: () => 'nonce',
    openBrowser: async (url) => {
      h.opened.push(url);
      return options.openOk ?? true;
    },
    readFile: (path) => readFileSync(path, 'utf8'),
    waitForExit: async () => undefined,
    now: () => new Date('2026-10-07T09:30:00Z'),
  };
  return h;
}

const text = (h: Harness) => h.out.join('\n');

describe('引数', () => {
  it('parseArgs', () => {
    assert.deepEqual(parseArgs(['--project', 'x', '--no-open']), { project: 'x', open: false, help: false });
    assert.deepEqual(parseArgs(['--project-ref=y']), { project: 'y', open: true, help: false });
    assert.equal(parseArgs(['--from-file', 'a.json']).fromFile, 'a.json');
    assert.equal(parseArgs(['-h']).help, true);
  });
});

describe('基本フロー', () => {
  it('URL入力 → トークン入力 → 診断 → レポート配信 → ブラウザ起動', async () => {
    const h = harness({ answers: [`https://supabase.com/dashboard/project/${REF}/editor`], secrets: ['sbp_fc_scoped'] });
    assert.equal(await runCli(h.deps), 0);
    const out = text(h);
    assert.match(out, /AIで作ったSupabaseアプリを公開する前に、セキュリティ設定を確認します。/);
    assert.ok(out.indexOf('プロジェクトを指定してください') < out.indexOf('アクセストークンを貼り付けてください'), 'プロジェクト → トークンの順');
    assert.match(out, /Supabaseの設定を確認しています\.\.\./);
    assert.match(out, /修正してから公開することをおすすめします（🔴 危険 2件/);
    assert.deepEqual(h.refsUsed, [REF]);
    assert.deepEqual(h.tokensUsed, ['sbp_fc_scoped']);
    assert.equal(h.opened.length, 1);
    assert.match(out, /ブラウザでレポートを開きました。/);
    assert.ok(h.servedHtml?.includes('公開前チェック結果'));
    assert.doesNotMatch(out, /広い権限/);
  });

  it('ブラウザを開けなければURLを表示する', async () => {
    const h = harness({ answers: [REF], secrets: ['sbp_fc_x'], openOk: false });
    await runCli(h.deps);
    assert.match(text(h), /次のURLをブラウザで開くと/);
    assert.match(text(h), /http:\/\/127\.0\.0\.1:5555\/r\//);
  });

  it('--no-open ならブラウザを開かない', async () => {
    const h = harness({ argv: ['--no-open', '--project', REF], secrets: ['sbp_fc_x'] });
    await runCli(h.deps);
    assert.equal(h.opened.length, 0);
    assert.equal(h.asked.length, 0, '--project 指定時はプロジェクトを聞かない');
  });
});

describe('プロジェクト指定', () => {
  it('不正な入力は日本語で再入力を案内する', async () => {
    const h = harness({ answers: ['my-app', 'https://evil.example/project/abc', REF], secrets: ['sbp_fc_x'] });
    assert.equal(await runCli(h.deps), 0);
    assert.equal(h.asked.length, 3);
    assert.equal(text(h).match(/プロジェクトとして読み取れませんでした/g)?.length, 2);
    assert.deepEqual(h.refsUsed, [REF]);
  });

  it('5回続けて不正なら終了する', async () => {
    const h = harness({ answers: ['a', 'b', 'c', 'd', 'e'] });
    assert.equal(await runCli(h.deps), 1);
    assert.match(h.err.join('\n'), /プロジェクトを指定できなかったため終了します/);
  });

  it('--project の値が不正ならエラー', async () => {
    const h = harness({ argv: ['--project', 'nope'] });
    assert.equal(await runCli(h.deps), 1);
    assert.match(h.err.join('\n'), /--project の値をプロジェクトとして読み取れませんでした/);
  });

  it('プロジェクトが見つからなければ再入力', async () => {
    const other = 'zyxwvutsrqponmlkjihg';
    const h = harness({ answers: [REF, other], secrets: ['sbp_fc_x'], responses: ['not_found', SAMPLE_RESULT] });
    assert.equal(await runCli(h.deps), 0);
    assert.deepEqual(h.refsUsed, [REF, other]);
    assert.match(text(h), /プロジェクトが見つかりません/);
  });
});

describe('アクセストークン', () => {
  it('環境変数があれば入力を求めない', async () => {
    const h = harness({ env: { SUPABASE_ACCESS_TOKEN: 'sbp_fc_env' }, answers: [REF] });
    assert.equal(await runCli(h.deps), 0);
    assert.equal(h.secretAsked, 0);
    assert.deepEqual(h.tokensUsed, ['sbp_fc_env']);
    assert.match(text(h), /環境変数 SUPABASE_ACCESS_TOKEN のトークンを使います/);
  });

  it('「?」で作り方を案内し、空入力では再入力を促す', async () => {
    const h = harness({ answers: [REF], secrets: ['?', '', 'sbp_fc_x'] });
    assert.equal(await runCli(h.deps), 0);
    const out = text(h);
    assert.match(out, /トークンの作り方:/);
    assert.match(out, /https:\/\/supabase\.com\/dashboard\/account\/tokens/);
    assert.match(out, /権限は「Advisors: Read」だけ/);
    assert.match(out, /トークンが入力されていません/);
    assert.equal(h.secretAsked, 3);
  });

  it('Legacy トークンなら警告する', async () => {
    const h = harness({ answers: [REF], secrets: ['sbp_TEST_ONLY_LEGACY'] });
    await runCli(h.deps);
    assert.match(text(h), /このトークンは広い権限を持っています。可能であれば対象プロジェクトのAdvisors: Readだけを持つScoped Tokenの使用をおすすめします。/);
    assert.match(h.servedHtml ?? '', /このトークンは広い権限を持っています。/);
  });

  it('無効なトークンなら再入力（入力したトークンの場合）', async () => {
    const h = harness({ answers: [REF], secrets: ['sbp_fc_wrong', 'sbp_fc_right'], responses: ['invalid_token', SAMPLE_RESULT] });
    assert.equal(await runCli(h.deps), 0);
    assert.deepEqual(h.tokensUsed, ['sbp_fc_wrong', 'sbp_fc_right']);
    assert.match(text(h), /アクセストークンが無効です/);
  });

  it('権限不足を案内し、3回失敗したら終了する', async () => {
    const h = harness({ answers: [REF], secrets: ['sbp_fc_1', 'sbp_fc_2', 'sbp_fc_3'], responses: ['forbidden', 'forbidden', 'forbidden'] });
    assert.equal(await runCli(h.deps), 1);
    assert.match(text(h), /Advisors」を Read にしてください/);
    assert.equal(h.tokensUsed.length, 3);
  });

  it('環境変数のトークンが無効なら、入力を求めずに終了する', async () => {
    const h = harness({ env: { SUPABASE_ACCESS_TOKEN: 'sbp_fc_bad' }, answers: [REF], responses: ['invalid_token'] });
    assert.equal(await runCli(h.deps), 1);
    assert.equal(h.secretAsked, 0);
    assert.match(h.err.join('\n'), /環境変数 SUPABASE_ACCESS_TOKEN のトークンを確認/);
  });

  it('ネットワークエラーは日本語で案内して終了する', async () => {
    const h = harness({ answers: [REF], secrets: ['sbp_fc_x'], responses: ['network'] });
    assert.equal(await runCli(h.deps), 1);
    assert.match(text(h), /Supabaseに接続できませんでした/);
  });

  it('トークンの値を出力にもHTMLにも含めない', async () => {
    const token = 'sbp_fc_secret_value_123456';
    const h = harness({ answers: [REF], secrets: [token] });
    await runCli(h.deps);
    assert.ok(!text(h).includes(token));
    assert.ok(!h.err.join('').includes(token));
    assert.ok(!(h.servedHtml ?? '').includes(token));
  });
});

describe('不完全な診断', () => {
  it('ターミナルでも確認できなかった項目があることを伝える', async () => {
    const h = harness({ answers: [REF], secrets: ['sbp_fc_x'] }); // サンプルには未知の項目が含まれる
    await runCli(h.deps);
    assert.match(text(h), /確認できなかった項目があります/);
    assert.match(h.servedHtml ?? '', /この診断結果には確認できなかった項目があります。/);
  });
});

describe('--from-file（通信なし）', () => {
  it('保存した結果からレポートを作る', async () => {
    const h = harness({ argv: ['--from-file', SAMPLE_PATH] });
    assert.equal(await runCli(h.deps), 0);
    assert.equal(h.secretAsked, 0);
    assert.equal(h.tokensUsed.length, 0);
    assert.ok(h.servedHtml?.includes('修正してから公開することをおすすめします'));
  });

  it('読めないファイルはエラー', async () => {
    const h = harness({ argv: ['--from-file', '/nonexistent.json'] });
    assert.equal(await runCli(h.deps), 1);
  });
});

describe('実際のCLIプロセス（--from-file / 通信なし）', () => {
  it('起動してローカルでレポートを配信し、Ctrl+C で終了する', async () => {
    const bin = fileURLToPath(new URL('../src/cli/index.js', import.meta.url));
    const child = spawnInterruptible(process.execPath, [bin, '--from-file', SAMPLE_PATH, '--no-open']);
    try {
      child.stdin.end();
      let out = '';
      // 起動にかかる時間は、子プロセスが起動してから測る（Windows の Ctrl+C の仲立ちの準備時間を含めない）
      await child.ready;
      const url = await new Promise<string>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`timeout: ${out}`)), 10_000);
        child.stdout.on('data', (chunk: Buffer) => {
          out += chunk.toString();
          const m = out.match(/http:\/\/127\.0\.0\.1:\d+\/r\/[0-9a-f]{32}/);
          if (m) {
            clearTimeout(timer);
            resolve(m[0]);
          }
        });
        void child.exited.then(() => reject(new Error(`exited early: ${out}`)));
      });
      const res = await fetch(url);
      assert.equal(res.status, 200);
      const html = await res.text();
      assert.match(html, /公開前チェック結果/);
      assert.match(res.headers.get('content-security-policy') ?? '', /default-src 'none'/);

      child.interrupt();
      assert.equal(await child.exited, 0);
      assert.match(out, /終了しました/);
    } finally {
      // 失敗したときも、子プロセスを残さない（残るとテストのプロセスが終われない）
      child.kill();
    }
  });
});

describe('サーバーの終了方式（lifecycle）', () => {
  it('Ctrl+C（SIGINT）で終了する', async () => {
    const { EventEmitter } = await import('node:events');
    const { waitForExit } = await import('../src/cli/lifecycle.js');
    const signals = new EventEmitter();
    const p = waitForExit({ idleMs: 60_000, lastActivity: () => Date.now(), signals, checkEveryMs: 5 });
    signals.emit('SIGINT');
    assert.equal(await p, 'signal');
    assert.equal(signals.listenerCount('SIGINT'), 0, 'リスナーを残さない');
  });

  it('最後の表示から一定時間たつと終了し、表示があれば延長される', async () => {
    const { EventEmitter } = await import('node:events');
    const { ActivityTracker, waitForExit } = await import('../src/cli/lifecycle.js');
    let clock = 0;
    const tracker = new ActivityTracker(() => clock);
    let done = false;
    const p = waitForExit({ idleMs: 100, lastActivity: () => tracker.lastActivity(), signals: new EventEmitter(), now: () => clock, checkEveryMs: 2 }).then((r) => {
      done = true;
      return r;
    });
    clock = 90;
    tracker.touch(); // ここで表示があった
    clock = 150; // 最後の表示から60しか経っていない
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(done, false, '表示中は終了しない');
    clock = 200;
    assert.equal(await p, 'idle');
  });

  it('自動終了までの時間をターミナルで案内する', async () => {
    const h = harness({ answers: [REF], secrets: ['sbp_fc_x'] });
    h.deps.idleExitMinutes = 30;
    await runCli(h.deps);
    assert.match(text(h), /最後にレポートを表示してから30分たつと自動で終了します。終了後も、表示中のページはそのまま見られます。/);
  });
});

describe('プロジェクト指定（入力形式）', () => {
  it('Project Ref を直接入力できる', async () => {
    const h = harness({ answers: [REF], secrets: ['sbp_fc_x'] });
    assert.equal(await runCli(h.deps), 0);
    assert.deepEqual(h.refsUsed, [REF]);
  });

  it('Dashboard URL（各画面のURL）から Project Ref を取り出す', async () => {
    for (const url of [
      `https://supabase.com/dashboard/project/${REF}`,
      `https://supabase.com/dashboard/project/${REF}/advisors/security`,
      `https://supabase.com/dashboard/project/${REF}?showConnect=true`,
      `https://${REF}.supabase.co`,
    ]) {
      const h = harness({ answers: [url], secrets: ['sbp_fc_x'] });
      assert.equal(await runCli(h.deps), 0, url);
      assert.deepEqual(h.refsUsed, [REF], url);
    }
  });
});
