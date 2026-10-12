// Phase 4.7: Windows の専用ウィンドウ（WebView2）で表示する方式のテスト。
// 専用ウィンドウの本体（native/windows-host/host.cpp）は Windows でしか動かないため、
// ここでは同じ形式でやり取りする代役（test/helpers/fake-window-host.ts）を使って Node.js 側を確かめる。
// host.cpp そのものは、安全のための設定が入っていることを静的に確かめる。

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { windowsBaseEnv } from './helpers/interruptible.js';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { deflateRawSync } from 'node:zlib';
import { powershellMessageBoxScript, showFatalMessage } from '../src/app/fatal-message.js';
import { defaultInstallBase, HOST_EXE_NAME, installHostFiles, LOADER_DLL_NAME, readSeaHostFiles } from '../src/app/host-install.js';
import { runApp, type AppRunDeps } from '../src/app/run.js';
import { formatHostCommand, parseHostLine, startWindowHost, type HostExit, type WindowHost } from '../src/app/window-host.js';
import { chooseMode } from '../src/cli/mode.js';
import { guardStdio } from '../src/cli/standalone.js';
import { isAllowedExternalUrl } from '../src/shared/url.js';

const FAKE_HOST = fileURLToPath(new URL('./helpers/fake-window-host.js', import.meta.url));
const BIN = fileURLToPath(new URL('../src/cli/index.js', import.meta.url));
const GUARD = fileURLToPath(new URL('./helpers/network-guard.js', import.meta.url));
const PKG_ROOT = fileURLToPath(new URL('../..', import.meta.url));
const HOST_CPP = join(PKG_ROOT, 'native', 'windows-host', 'host.cpp');
const BUILD_SCRIPT = new URL('../../scripts/build-windows-exe.mjs', import.meta.url).href;
const RELEASE_EXE = join(PKG_ROOT, 'release', 'windows', 'koukai-check-0.1.0-win-x64.exe');
const APP_URL = 'http://127.0.0.1:43210/r/0123456789abcdef0123456789abcdef/';

const roots: string[] = [];
after(() => roots.forEach((r) => rmSync(r, { recursive: true, force: true })));
function tempDir(prefix = 'kc-win-'): string {
  const d = mkdtempSync(join(tmpdir(), prefix));
  roots.push(d);
  return d;
}

/** 代役を起動する startWindowHost（環境変数で動きを決める） */
function fakeHost(env: Record<string, string>, url = APP_URL): WindowHost {
  return startWindowHost({
    command: process.execPath,
    args: [FAKE_HOST],
    url,
    spawnImpl: ((cmd: string, args: string[], opts: object) => spawn(cmd, args, { ...opts, env: { PATH: process.env.PATH ?? '', ...env } })) as typeof spawn,
  });
}

describe('配布物を Git にコミットしない', () => {
  it('Windows の exe・SHA256SUMS・ビルド情報は .gitignore で除外する（GitHub Releases で配布する）', () => {
    const ignore = readFileSync(join(PKG_ROOT, '.gitignore'), 'utf8');
    for (const line of ['release/windows/*.exe', 'release/windows/SHA256SUMS.txt', 'release/windows/THIRD-PARTY-NOTICES.txt', 'release/windows/BUILD-INFO.txt']) {
      assert.ok(ignore.split(/\r?\n/).includes(line), line);
    }
  });
});

describe('専用ウィンドウとのやり取り（形式）', () => {
  it('専用ウィンドウからの行を解釈する。知らない行は無視する', () => {
    assert.deepEqual(parseHostLine('READY'), { kind: 'ready' });
    assert.deepEqual(parseHostLine('PICKED C:\\Users\\山田\\Desktop\\テスト アプリ\r'), { kind: 'picked', path: 'C:\\Users\\山田\\Desktop\\テスト アプリ' });
    assert.deepEqual(parseHostLine('PICKED '), { kind: 'pick-failed' });
    assert.deepEqual(parseHostLine('PICK-CANCELLED'), { kind: 'pick-cancelled' });
    assert.deepEqual(parseHostLine('EXTERNAL https://supabase.com/docs'), { kind: 'external', url: 'https://supabase.com/docs' });
    assert.deepEqual(parseHostLine('NO-RUNTIME'), { kind: 'no-runtime' });
    assert.deepEqual(parseHostLine('FAILED 80004005'), { kind: 'failed', code: '80004005' });
    assert.deepEqual(parseHostLine('CLOSED'), { kind: 'closed' });
    assert.equal(parseHostLine('ready'), undefined);
    assert.equal(parseHostLine('EVAL alert(1)'), undefined);
    assert.equal(parseHostLine(`PICKED ${'a'.repeat(20000)}`), undefined);
  });

  it('専用ウィンドウへの指示に改行を混ぜられない（1行の区切りを崩して別の指示を足せない）', () => {
    assert.equal(formatHostCommand({ kind: 'navigate', url: APP_URL }), `NAVIGATE ${APP_URL}\n`);
    assert.equal(formatHostCommand({ kind: 'pick' }), 'PICK\n');
    assert.equal(formatHostCommand({ kind: 'quit' }), 'QUIT\n');
    assert.throws(() => formatHostCommand({ kind: 'open-external', url: 'https://supabase.com/\nQUIT' }), /改行/);
  });

  it('127.0.0.1 の決まった形の URL 以外は、専用ウィンドウに渡さない', () => {
    for (const url of ['http://localhost:1/r/0123456789abcdef0123456789abcdef/', 'https://example.com/', 'http://127.0.0.1:1/r/xyz/', 'file:///C:/']) {
      assert.throws(() => startWindowHost({ command: 'never-run', url }), /渡せない URL/, url);
    }
  });
});

describe('既定のブラウザで開いてよいリンク', () => {
  it('画面に出している公式ドキュメント（https）だけを許可する', () => {
    for (const ok of [
      'https://supabase.com/dashboard/account/tokens',
      'https://supabase.com/docs/guides/database/database-linter?lint=0013_rls_disabled_in_public',
      'https://status.supabase.com/',
      'https://docs.expo.dev/guides/environment-variables/',
      'https://nextjs.org/docs',
      'https://firebase.google.com/docs/rules',
    ]) {
      assert.equal(isAllowedExternalUrl(ok), true, ok);
    }
    for (const ng of [
      'http://supabase.com/',
      'https://supabase.com.evil.example/',
      'https://evilsupabase.com/',
      'https://user:pass@supabase.com/',
      'https://supabase.com:8443/',
      'https://example.com/',
      'file:///C:/Windows/System32/calc.exe',
      'javascript:alert(1)',
      'ms-settings:privacy',
      'https://supabase.com/ "&calc',
      'https://supabase.com/\u0000',
      `https://supabase.com/${'a'.repeat(3000)}`,
      42,
    ]) {
      assert.equal(isAllowedExternalUrl(ng), false, String(ng));
    }
  });
});

describe('専用ウィンドウの起動と終了（代役で確認）', () => {
  it('URL を標準入力で渡し、フォルダ選択の結果を受け取り、QUIT で閉じる', async () => {
    const dir = tempDir();
    const logFile = join(dir, 'log.txt');
    const host = fakeHost({ FAKE_HOST_PICK: 'C:\\Users\\山田\\テストアプリ', FAKE_HOST_LOG: logFile });
    await host.ready;
    assert.deepEqual(await host.pickFolder(), { kind: 'picked', path: 'C:\\Users\\山田\\テストアプリ' });
    await host.close();
    assert.deepEqual(await host.exited, { kind: 'closed' });
    assert.deepEqual(readFileSync(logFile, 'utf8').trim().split('\n'), [`NAVIGATE ${APP_URL}`, 'PICK', 'QUIT']);
  });

  it('キャンセルされたら cancelled を返す。同時に2回頼んでも、選択画面は1回だけ', async () => {
    const dir = tempDir();
    const logFile = join(dir, 'log.txt');
    const host = fakeHost({ FAKE_HOST_PICK: 'cancel', FAKE_HOST_LOG: logFile });
    await host.ready;
    const [a, b] = await Promise.all([host.pickFolder(), host.pickFolder()]);
    assert.deepEqual(a, { kind: 'cancelled' });
    assert.deepEqual(b, { kind: 'cancelled' });
    await host.close();
    assert.equal(readFileSync(logFile, 'utf8').split('\n').filter((l) => l === 'PICK').length, 1);
  });

  it('リンクは許可したものだけ OPEN-EXTERNAL で返す（それ以外は何も返さない）', async () => {
    const dir = tempDir();
    const logFile = join(dir, 'log.txt');
    const host = fakeHost({
      FAKE_HOST_LOG: logFile,
      FAKE_HOST_EXTERNAL: 'https://supabase.com/docs|https://evil.example/|http://supabase.com/|file:///C:/x',
    });
    await host.ready;
    await new Promise((r) => setTimeout(r, 200));
    await host.close();
    const lines = readFileSync(logFile, 'utf8').trim().split('\n');
    assert.deepEqual(
      lines.filter((l) => l.startsWith('OPEN-EXTERNAL')),
      ['OPEN-EXTERNAL https://supabase.com/docs'],
    );
  });

  it('利用者がウィンドウを閉じたら closed、ランタイムがなければ no-runtime、黙って落ちたら crashed', async () => {
    const closed = fakeHost({ FAKE_HOST_MODE: 'close-after-ready' });
    assert.deepEqual(await closed.exited, { kind: 'closed' });
    const noRuntime = fakeHost({ FAKE_HOST_MODE: 'no-runtime' });
    assert.deepEqual(await noRuntime.exited, { kind: 'no-runtime' });
    const crashed = fakeHost({ FAKE_HOST_MODE: 'crash' });
    assert.deepEqual(await crashed.exited, { kind: 'crashed' });
    // 終わったあとのフォルダ選択は、待たずに unavailable
    assert.deepEqual(await crashed.pickFolder(), { kind: 'unavailable' });
  });

  it('フォルダ選択の途中でウィンドウが落ちても、待ち続けない', async () => {
    const host = startWindowHost({
      command: process.execPath,
      args: ['-e', 'process.stdin.once("data", () => { process.stdout.write("READY\\n"); setTimeout(() => process.exit(1), 150); })'],
      url: APP_URL,
    });
    await host.ready;
    assert.deepEqual(await host.pickFolder(), { kind: 'cancelled' });
    assert.deepEqual(await host.exited, { kind: 'crashed' });
  });

  it('起動できないコマンドなら crashed（例外で落ちない）', async () => {
    const host = startWindowHost({ command: join(tempDir(), 'no-such-host.exe'), url: APP_URL });
    assert.deepEqual(await host.exited, { kind: 'crashed' });
  });
});

describe('専用ウィンドウの部品の配置', () => {
  const files = [
    { name: HOST_EXE_NAME, data: new Uint8Array(Buffer.from('MZ fake host')) },
    { name: LOADER_DLL_NAME, data: new Uint8Array(Buffer.from('MZ fake loader')) },
  ];

  it('内容のハッシュごとのフォルダに置き、2回目は書き直さない', () => {
    const base = tempDir();
    const exe = installHostFiles(files, base);
    assert.equal(readFileSync(exe, 'utf8'), 'MZ fake host');
    assert.match(exe, /[\\/][0-9a-f]{16}[\\/]koukai-check-window\.exe$/);
    assert.equal(installHostFiles(files, base), exe);
    assert.deepEqual(readdirSync(join(exe, '..')).sort(), [LOADER_DLL_NAME, HOST_EXE_NAME].sort(), '一時ファイルが残らない');
  });

  it('置いたファイルが書き換えられていたら、元の内容に戻してから使う', () => {
    const base = tempDir();
    const exe = installHostFiles(files, base);
    writeFileSync(exe, 'tampered');
    assert.equal(readFileSync(installHostFiles(files, base), 'utf8'), 'MZ fake host');
  });

  it('古い版のフォルダは消す。関係のないファイルは消さない', () => {
    const base = tempDir();
    mkdirSync(join(base, '0123456789abcdef'));
    writeFileSync(join(base, 'keep.txt'), 'x');
    const exe = installHostFiles(files, base);
    assert.equal(existsSync(join(base, '0123456789abcdef')), false);
    assert.equal(existsSync(join(base, 'keep.txt')), true);
    assert.equal(existsSync(exe), true);
  });

  it('不正な名前・部品の不足は受け付けない', () => {
    const base = tempDir();
    assert.throws(() => installHostFiles([{ name: '..\\evil.exe', data: new Uint8Array(1) }, files[0]!], base), /名前が不正/);
    assert.throws(() => installHostFiles([files[1]!], base), /部品がありません/);
  });

  it('置き場所は %LOCALAPPDATA%\\koukai-check\\window（不正な値なら既定の場所）', () => {
    assert.equal(defaultInstallBase({ LOCALAPPDATA: 'C:\\Users\\a\\AppData\\Local' }), join('C:\\Users\\a\\AppData\\Local', 'koukai-check', 'window'));
    assert.match(defaultInstallBase({ LOCALAPPDATA: '\\\\attacker\\share' }), /AppData[\\/]Local[\\/]koukai-check[\\/]window$/);
    assert.match(defaultInstallBase({}), /AppData[\\/]Local[\\/]koukai-check[\\/]window$/);
  });

  it('exe の中の部品が読めなければ undefined（通常の node では SEA の部品はない）', () => {
    assert.equal(readSeaHostFiles(() => { throw new Error('not sea'); }), undefined);
    const read = readSeaHostFiles((key) => new TextEncoder().encode(key).buffer as ArrayBuffer);
    assert.deepEqual(read?.map((f) => f.name), [HOST_EXE_NAME, LOADER_DLL_NAME]);
  });
});

describe('専用ウィンドウでの起動の流れ（runApp）', () => {
  function stubHost(exit: HostExit) {
    const state = { picks: 0, closed: false };
    let resolveExit: (e: HostExit) => void = () => undefined;
    const host: WindowHost = {
      ready: Promise.resolve(),
      exited: new Promise<HostExit>((r) => (resolveExit = r)),
      pickFolder: async () => {
        state.picks++;
        return { kind: 'cancelled' };
      },
      close: async () => {
        state.closed = true;
        resolveExit(exit);
      },
    };
    return { host, state };
  }

  function deps(overrides: Partial<AppRunDeps>): AppRunDeps {
    return {
      print: () => undefined,
      createNonce: () => 'nonce',
      pickFolder: async () => assert.fail('専用ウィンドウがあるときは、PowerShell などのフォルダ選択を使わない'),
      createClient: () => assert.fail('使わない'),
      openBrowser: async () => assert.fail('専用ウィンドウがあるときは、既定のブラウザを開かない'),
      touch: () => undefined,
      waitForExit: (q) => q,
      now: () => new Date(),
      ...overrides,
    };
  }

  it('「終了する」で専用ウィンドウとサーバーを止め、終了コード0', async () => {
    const stub = stubHost({ kind: 'closed' });
    let url = '';
    const code = await runApp(
      deps({
        openWindow: (u) => {
          url = u;
          // 画面の「フォルダを選ぶ」→「終了する」を押したことにする
          setTimeout(async () => {
            const home = await (await fetch(u)).text();
            const csrf = home.match(/name="csrf" value="([0-9a-f]+)"/)?.[1] ?? '';
            const origin = new URL(u).origin;
            const post = (route: string) =>
              fetch(`${u}${route}`, { method: 'POST', redirect: 'manual', headers: { origin, 'content-type': 'application/x-www-form-urlencoded' }, body: `csrf=${csrf}` });
            await post('pick');
            await post('quit');
          }, 10);
          return stub.host;
        },
      }),
    );
    assert.equal(code, 0);
    assert.equal(stub.state.closed, true);
    assert.equal(stub.state.picks, 1, 'フォルダ選択は専用ウィンドウに頼む');
    await assert.rejects(fetch(url), 'サーバーも止まっている');
  });

  it('利用者がウィンドウを閉じたら、サーバーを止めて終了コード0', async () => {
    let resolveExit: (e: HostExit) => void = () => undefined;
    const host: WindowHost = { ready: Promise.resolve(), exited: new Promise((r) => (resolveExit = r)), pickFolder: async () => ({ kind: 'cancelled' }), close: async () => undefined };
    let url = '';
    const code = await runApp(
      deps({
        openWindow: (u) => {
          url = u;
          setTimeout(() => resolveExit({ kind: 'closed' }), 10);
          return host;
        },
      }),
    );
    assert.equal(code, 0);
    await assert.rejects(fetch(url));
  });

  it('ウィンドウが黙って落ちたら、案内を出して終了コード1。ランタイムがない場合は案内を重ねない', async () => {
    for (const [exit, expectNotice] of [
      [{ kind: 'crashed' }, true],
      [{ kind: 'no-runtime' }, false],
      [{ kind: 'failed', code: 'X' }, false],
    ] as const) {
      let notices = 0;
      const host: WindowHost = { ready: Promise.resolve(), exited: Promise.resolve(exit), pickFolder: async () => ({ kind: 'cancelled' }), close: async () => undefined };
      const code = await runApp(deps({ openWindow: () => host, onWindowCrashed: async () => void notices++ }));
      assert.equal(code, 1);
      assert.equal(notices, expectNotice ? 1 : 0, exit.kind);
    }
  });
});

describe('実際のプロセスでの確認（代役の専用ウィンドウ）', () => {
  /** --dev-window-host に .js を渡すと、いまの Node.js で代役を起動する（.sh・.cmd を使わないので、どのOSでも同じ） */
  const wrapper = () => FAKE_HOST;

  function startProcess(env: Record<string, string>) {
    const dir = tempDir();
    const urlFile = join(dir, 'url.txt');
    const child = spawn(process.execPath, ['--import', pathToFileURL(GUARD).href, BIN, `--dev-window-host=${wrapper()}`], {
      env: { PATH: process.env.PATH ?? '', HOME: dir, FAKE_HOST_URL_FILE: urlFile, ...windowsBaseEnv(), ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    child.stdout.on('data', (c: Buffer) => (out += c.toString()));
    child.stderr.on('data', (c: Buffer) => (out += c.toString()));
    const exited = new Promise<number | null>((r) => child.once('exit', (c) => r(c)));
    const url = (async () => {
      for (let i = 0; i < 150; i++) {
        if (existsSync(urlFile) && readFileSync(urlFile, 'utf8')) return readFileSync(urlFile, 'utf8');
        await new Promise((r) => setTimeout(r, 100));
      }
      throw new Error(`URL が渡されませんでした: ${out}`);
    })();
    return { url, exited, output: () => out };
  }

  it('フォルダを選ぶ → チェック結果 → 「終了する」で、ウィンドウ・サーバー・プロセスが終わる。ブラウザは開かない', async () => {
    const app = tempDir('kc-app-');
    writeFileSync(join(app, 'package.json'), JSON.stringify({ dependencies: { expo: '51.0.0', '@supabase/supabase-js': '2.0.0' } }));
    const p = startProcess({ FAKE_HOST_PICK: app });
    const url = await p.url;
    assert.match(url, /^http:\/\/127\.0\.0\.1:\d+\/r\/[0-9a-f]{32}\/$/);
    const home = await (await fetch(url)).text();
    assert.match(home, /チェックするアプリのフォルダを選ぶ/);
    const csrf = home.match(/name="csrf" value="([0-9a-f]+)"/)?.[1] ?? '';
    const origin = new URL(url).origin;
    const post = (route: string) =>
      fetch(`${url}${route}`, { method: 'POST', redirect: 'manual', headers: { origin, 'content-type': 'application/x-www-form-urlencoded' }, body: `csrf=${csrf}` });
    const picked = await post('pick');
    assert.equal(picked.status, 303);
    const scan = await (await fetch(new URL(picked.headers.get('location') ?? '', url))).text();
    assert.match(scan, /Supabase のチェックを始める/);
    assert.equal((await post('quit')).status, 200);
    assert.equal(await p.exited, 0);
    await assert.rejects(fetch(url));
    assert.doesNotMatch(p.output(), /ブラウザで画面を開きました|xdg-open/);
  });

  it('利用者が専用ウィンドウを閉じたら、プロセスも終了コード0で終わる', async () => {
    const p = startProcess({ FAKE_HOST_MODE: 'close-after-ready' });
    const url = await p.url;
    assert.equal(await p.exited, 0);
    await assert.rejects(fetch(url));
  });

  it('引数の判定：--dev-window-host は1つだけのときに限り受け付ける', () => {
    assert.deepEqual(chooseMode(['--dev-window-host=C:\\x.exe']), { kind: 'app', noOpen: false, windowHost: 'C:\\x.exe' });
    assert.deepEqual(chooseMode(['--dev-window-host=']), { kind: 'cli', argv: ['--dev-window-host='] });
    assert.deepEqual(chooseMode(['--dev-window-host=x', 'supabase']), { kind: 'cli', argv: ['--dev-window-host=x', 'supabase'] });
  });
});

describe('エラーの表示（黒い画面がない exe 版）', () => {
  it('Windows 以外では、ターミナルに表示する', async () => {
    const printed: string[] = [];
    await showFatalMessage('問題が起きました', { platform: 'linux', printError: (m) => printed.push(m) });
    assert.deepEqual(printed, ['問題が起きました']);
  });

  it('PowerShell に渡す文章は Base64 にして、引用符などでスクリプトが崩れない', () => {
    const script = powershellMessageBoxScript("');Remove-Item C:\\ -Recurse;('");
    assert.doesNotMatch(script, /Remove-Item/);
    const b64 = script.match(/FromBase64String\('([A-Za-z0-9+/=]+)'\)/)?.[1] ?? '';
    assert.equal(Buffer.from(b64, 'base64').toString('utf8'), "');Remove-Item C:\\ -Recurse;('");
  });

  it('標準出力が使えない環境でも落ちない（何もしない出力に差し替える）', () => {
    const target = {} as NodeJS.Process;
    for (const name of ['stdout', 'stderr']) {
      Object.defineProperty(target, name, { configurable: true, get: () => { throw new Error('EBADF'); } });
    }
    guardStdio(target);
    assert.doesNotThrow(() => target.stdout.write('x'));
    assert.doesNotThrow(() => target.stderr.write('x'));
  });
});

describe('専用ウィンドウ本体（host.cpp）の安全設定', () => {
  const cpp = readFileSync(HOST_CPP, 'utf8');
  const code = cpp.replace(/(^|\s)\/\/.*$/gm, '$1'); // コメントを除いた本体

  it('開発者ツール・ショートカット・ページからの呼び出し・パスワード保存などを無効にしている', () => {
    for (const setting of [
      'put_AreDevToolsEnabled(FALSE)',
      'put_AreBrowserAcceleratorKeysEnabled(FALSE)',
      'put_AreHostObjectsAllowed(FALSE)',
      'put_IsWebMessageEnabled(FALSE)',
      'put_IsStatusBarEnabled(FALSE)',
      'put_IsPasswordAutosaveEnabled(FALSE)',
      'put_IsGeneralAutofillEnabled(FALSE)',
      'put_IsSwipeNavigationEnabled(FALSE)',
      'put_AllowExternalDrop(FALSE)',
      'put_IsReputationCheckingRequired(FALSE)',
      'put_IsInPrivateModeEnabled(TRUE)',
      'COREWEBVIEW2_PERMISSION_STATE_DENY',
    ]) {
      assert.ok(code.includes(setting), setting);
    }
  });

  it('アプリの画面以外への移動を止め、新しいウィンドウは開かず、外部リンクは Node.js 側の許可を待つ', () => {
    assert.match(code, /add_NavigationStarting[\s\S]*?/);
    assert.match(code, /if \(!IsAppUrl\(uri\)\) \{\s*args->put_Cancel\(TRUE\);\s*RequestExternal\(uri\);/);
    assert.match(code, /add_FrameNavigationStarting/);
    assert.match(code, /NewWindowRequested[\s\S]*?args->put_Handled\(TRUE\);/);
    // 外部で開くのは OPEN-EXTERNAL を受け取ったときだけ（https で、空白や引用符を含まないもの）
    const shellOpens = [...code.matchAll(/ShellExecuteW\(hwnd_, L"open", ([^,]+),/g)].map((m) => m[1]);
    assert.deepEqual(shellOpens, ['uri.c_str()', 'kRuntimePage']);
    assert.match(code, /bool ok = StartsWith\(uri, L"https:\/\/"\)/);
  });

  it('ページから使える仕組みや、外部への通信を持たない', () => {
    assert.doesNotMatch(code, /AddHostObjectToScript|add_WebMessageReceived|PostWebMessage|OpenDevToolsWindow|AddScriptToExecuteOnDocumentCreated|ExecuteScript/);
    assert.doesNotMatch(code, /WinHttp|InternetOpen|URLDownloadToFile|WSAStartup|socket\(/);
    const hosts = [...code.matchAll(/https?:\/\/([a-z0-9.-]+)/gi)].map((m) => m[1]);
    assert.deepEqual([...new Set(hosts)], ['developer.microsoft.com', '127.0.0.1']);
  });

  it('DLL は System32 と明示したパスからだけ読み込む', () => {
    assert.match(code, /SetDefaultDllDirectories\(LOAD_LIBRARY_SEARCH_SYSTEM32\)/);
    assert.match(code, /LoadLibraryExW\(path\.c_str\(\), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR \| LOAD_LIBRARY_SEARCH_SYSTEM32\)/);
  });

  it('フォルダ選択の画面は、専用ウィンドウを親にして表示する', () => {
    assert.match(code, /FOS_PICKFOLDERS/);
    assert.match(code, /dialog->Show\(hwnd_\)/);
    assert.match(code, /BringToFront\(\);/);
  });

  it('動作確認用の機能（KC_SMOKE_TEST）は、配布用のビルドでは有効にしない', () => {
    const blocks = [...cpp.matchAll(/#ifdef KC_SMOKE_TEST([\s\S]*?)#endif/g)];
    assert.equal(blocks.length, 2);
    assert.ok(cpp.split('KC_SMOKE_TEST').length - 1 === 2, 'ifdef の外で使っていない');
    assert.doesNotMatch(readFileSync(fileURLToPath(BUILD_SCRIPT), 'utf8'), /KC_SMOKE_TEST/);
  });
});

describe('Windows 版のビルド処理', () => {
  interface BuildModule {
    peSubsystem(buf: Buffer): number;
    setPeSubsystem(buf: Buffer, subsystem: number): Buffer;
    readZipEntries(zip: Buffer, names: string[]): Map<string, Buffer>;
    WEBVIEW2_SDK: { version: string; sha256: string };
    checkPeLayout(buf: Buffer): { blocks: number; entries: number };
    setManifest(buf: Buffer, manifest: Buffer): Promise<Buffer>;
    manifestsOf(buf: Buffer): Promise<Buffer[]>;
  }
  const load = async () => (await import(BUILD_SCRIPT)) as BuildModule;

  function fakePe(subsystem: number): Buffer {
    const buf = Buffer.alloc(0x200);
    buf.write('MZ', 0, 'latin1');
    buf.writeUInt32LE(0x80, 0x3c);
    buf.write('PE\0\0', 0x80, 'latin1');
    buf.writeUInt16LE(0x20b, 0x80 + 24);
    buf.writeUInt16LE(subsystem, 0x80 + 24 + 68);
    return buf;
  }

  it('PE の Subsystem をコンソール（3）からウィンドウのアプリ（2）に切り替える', async () => {
    const { peSubsystem, setPeSubsystem } = await load();
    const src = fakePe(3);
    const out = setPeSubsystem(src, 2);
    assert.equal(peSubsystem(out), 2);
    assert.equal(peSubsystem(src), 3, '元のバッファは書き換えない');
    assert.throws(() => setPeSubsystem(Buffer.alloc(0x200), 2), /PE ファイルではありません/);
  });

  it('NuGet パッケージ（ZIP）から必要なファイルだけを取り出す（無圧縮・deflate の両方）', async () => {
    const { readZipEntries } = await load();
    const zip = buildZip([
      { name: 'a.txt', data: Buffer.from('stored'), deflate: false },
      { name: 'build/native/include/WebView2.h', data: Buffer.from('#pragma once\n'.repeat(50)), deflate: true },
    ]);
    const out = readZipEntries(zip, ['build/native/include/WebView2.h']);
    assert.equal(out.get('build/native/include/WebView2.h')?.toString(), '#pragma once\n'.repeat(50));
    assert.throws(() => readZipEntries(zip, ['missing.dll']), /missing\.dll がありません/);
    assert.throws(() => readZipEntries(Buffer.from('not a zip'), ['x']), /ZIP の形式ではありません/);
  });

  it('WebView2 SDK は版と SHA256 を固定している', async () => {
    const { WEBVIEW2_SDK } = await load();
    assert.match(WEBVIEW2_SDK.version, /^1\.0\.\d+\.\d+$/);
    assert.match(WEBVIEW2_SDK.sha256, /^[0-9a-f]{64}$/);
  });

  it('生成した exe は「ウィンドウのアプリ」で、専用ウィンドウの部品が入っている', { skip: !existsSync(RELEASE_EXE) && 'npm run build:win で生成されていない' }, async () => {
    const { peSubsystem } = await load();
    const exe = readFileSync(RELEASE_EXE);
    assert.equal(peSubsystem(exe), 2, '黒い画面（コンソール）を開かない');
    const sums = readFileSync(join(PKG_ROOT, 'release', 'windows', 'SHA256SUMS.txt'), 'utf8');
    assert.match(sums, /koukai-check-window\.exe: [0-9a-f]{64}/);
    assert.match(sums, /WebView2Loader\.dll（WebView2 SDK [\d.]+）: [0-9a-f]{64}/);
    assert.ok(exe.includes(Buffer.from('windows-host/koukai-check-window.exe')), 'assets の名前が入っている');
    assert.ok(existsSync(join(PKG_ROOT, 'release', 'windows', 'THIRD-PARTY-NOTICES.txt')));
    // Release に添付するファイルすべての SHA256 と、ビルドしたソースのコミット
    for (const name of ['koukai-check-0.1.0-win-x64.exe', 'THIRD-PARTY-NOTICES.txt', 'BUILD-INFO.txt', 'README-ja.txt']) {
      assert.ok(sums.split(/\r?\n/).some((l) => /^[0-9a-f]{64}  /.test(l) && l.slice(66) === name), name);
    }
    assert.match(sums, /^# ソースのコミット: ([0-9a-f]{40}|unknown)/m);
    assert.match(readFileSync(join(PKG_ROOT, 'release', 'windows', 'BUILD-INFO.txt'), 'utf8'), /^ソースのコミット: ([0-9a-f]{40}|unknown)/m);
    // エクスプローラー・タスクマネージャーに「Node.js」ではなく「公開前チェック」と出る
    const ResEdit = await import('resedit');
    const res = ResEdit.NtExecutableResource.from(ResEdit.NtExecutable.from(exe, { ignoreCert: true }));
    const [vi] = ResEdit.Resource.VersionInfo.fromEntries(res.entries);
    const strings = vi?.getStringValues(vi.getAllLanguagesForStringValues()[0]!);
    assert.equal(strings?.FileDescription, '公開前チェック');
    assert.equal(strings?.ProductName, '公開前チェック');
    assert.ok(res.entries.some((e) => e.type === 10 && e.id === 'NODE_SEA_BLOB'), 'SEA の blob が入っている');
  });

  it('生成した exe の構造：セクションのファイル上の範囲が重ならず、再配置情報を最後まで正しく読める', { skip: !existsSync(RELEASE_EXE) && 'npm run build:win で生成されていない' }, async () => {
    const { checkPeLayout } = await load();
    const r = checkPeLayout(readFileSync(RELEASE_EXE));
    assert.ok(r.blocks > 0 && r.entries > 0);
  });

  it('PE の検査は、セクションの重なり・壊れた再配置情報を見つける', { skip: !existsSync(RELEASE_EXE) && 'npm run build:win で生成されていない' }, async () => {
    const { checkPeLayout } = await load();
    const exe = readFileSync(RELEASE_EXE);
    const pe = exe.readUInt32LE(0x3c);
    const opt = pe + 24;
    const first = opt + exe.readUInt16LE(pe + 20);
    // 1つ目のセクションのファイル上の大きさを広げ、次のセクションに重ねる（今回の警告の原因と同じ形）
    const overlap = Buffer.from(exe);
    overlap.writeUInt32LE(overlap.readUInt32LE(first + 16) + 0x1000, first + 16);
    assert.throws(() => checkPeLayout(overlap), /重なっています/);
    // 再配置情報の最初のブロックの大きさを壊す
    const relocRva = exe.readUInt32LE(opt + 112 + 40);
    let checked = false;
    for (let i = 0; i < exe.readUInt16LE(pe + 6); i++) {
      const o = first + i * 40;
      const va = exe.readUInt32LE(o + 12);
      if (relocRva >= va && relocRva < va + exe.readUInt32LE(o + 8)) {
        const broken = Buffer.from(exe);
        broken.writeUInt32LE(4, relocRva - va + exe.readUInt32LE(o + 20) + 4);
        assert.throws(() => checkPeLayout(broken), /壊れています/);
        checked = true;
      }
    }
    assert.ok(checked, '再配置情報のセクションが見つかる');
  });

  it('マニフェストを1つだけにする（MinGW-w64 が自動でリンクする既定のマニフェストを残さない）', { skip: !existsSync(RELEASE_EXE) && 'npm run build:win で生成されていない' }, async () => {
    const { setManifest, manifestsOf, checkPeLayout } = await load();
    const manifest = readFileSync(join(PKG_ROOT, 'native', 'windows-host', 'app.manifest'));
    const out = await setManifest(readFileSync(RELEASE_EXE), manifest);
    const found = await manifestsOf(out);
    assert.equal(found.length, 1);
    assert.ok(found[0]?.equals(manifest));
    checkPeLayout(out);
  });
});

/** テスト用の小さな ZIP を作る */
function buildZip(entries: { name: string; data: Buffer; deflate: boolean }[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const e of entries) {
    const body = e.deflate ? deflateRawSync(e.data) : e.data;
    const name = Buffer.from(e.name);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(e.deflate ? 8 : 0, 8);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(e.data.length, 22);
    local.writeUInt16LE(name.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(e.deflate ? 8 : 0, 10);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(e.data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, name, body);
    centrals.push(central, name);
    offset += 30 + name.length + body.length;
  }
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, end]);
}
