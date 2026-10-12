#!/usr/bin/env node
// koukai-check のエントリーポイント（npx koukai-check と、Windows の exe 版の両方）。
// 引数なしでは一般ユーザー向けの画面（フォルダ選択）を開き、`supabase` サブコマンドでは開発用の CLI を動かす。
//   ・Windows の exe 版：専用ウィンドウ（WebView2）で画面を表示する。黒い画面もブラウザも使わない
//   ・npx：既定のブラウザで画面を開く

import { readFileSync } from 'node:fs';
import process from 'node:process';
import { openBrowser } from '../report/open-browser.js';
import { createNonce, startReportServer } from '../report/server.js';
import { createManagementClient } from '../supabase/client.js';
import { showFatalMessage } from '../app/fatal-message.js';
import { pickFolder } from '../app/folder-picker.js';
import { defaultInstallBase, installHostFiles, readSeaHostFiles } from '../app/host-install.js';
import { runApp } from '../app/run.js';
import { startWindowHost } from '../app/window-host.js';
import { runCli } from './app.js';
import { chooseMode, MAIN_HELP } from './mode.js';
import { ActivityTracker, waitForExit } from './lifecycle.js';
import { ask, askSecret } from './prompt.js';
import {
  guardStdio,
  HOST_INSTALL_FAILED_MESSAGE,
  isStandaloneExe,
  readStandaloneAsset,
  STANDALONE_ARGS_MESSAGE,
  UNEXPECTED_ERROR_MESSAGE,
  WINDOW_CRASHED_MESSAGE,
} from './standalone.js';
import { MIN_NODE_MAJOR, nodeTooOldMessage } from './texts.js';

/** 最後にレポートが表示されてから、この時間がたったら自動で終了する（ブラウザで表示する場合だけ） */
export const IDLE_EXIT_MINUTES = 30;

const activity = new ActivityTracker();
/** Windows の exe 版（専用ウィンドウで表示する） */
const windowsExe = process.platform === 'win32' && isStandaloneExe();
let hostExe: string | undefined;

if (windowsExe) guardStdio();

async function waitUntilDone(): Promise<void> {
  const reason = await waitForExit({ idleMs: IDLE_EXIT_MINUTES * 60 * 1000, lastActivity: () => activity.lastActivity(), signals: process });
  process.stdout.write(
    reason === 'idle'
      ? `\nレポートが${IDLE_EXIT_MINUTES}分間表示されなかったため、表示用のサーバーを終了しました（表示中のページはそのまま見られます）。\n`
      : '\n終了しました。\n',
  );
}

const nodeMajor = Number(process.versions.node.split('.')[0]);
if (!Number.isFinite(nodeMajor) || nodeMajor < MIN_NODE_MAJOR) {
  console.error(nodeTooOldMessage(process.versions.node));
  process.exit(1);
}

/** 専用ウィンドウの exe のパス。exe 版なら中に入っている部品を取り出して置く */
function resolveWindowHost(devPath: string | undefined): string | undefined {
  if (devPath) return devPath;
  if (!windowsExe) return undefined;
  const files = readSeaHostFiles(readStandaloneAsset);
  if (!files) throw new HostUnavailable();
  try {
    return installHostFiles(files, defaultInstallBase());
  } catch {
    throw new HostUnavailable();
  }
}

class HostUnavailable extends Error {}

/**
 * 専用ウィンドウの起動方法。開発・テスト用の --dev-window-host に .js を渡した場合は、いまの Node.js で起動する
 * （Windows では .sh・.cmd をシェルなしで起動できないため。exe 版では使わない）
 */
function hostCommand(path: string): { command: string; args: string[] } {
  return !windowsExe && /\.[cm]?js$/i.test(path) ? { command: process.execPath, args: [path] } : { command: path, args: [] };
}

async function main(): Promise<number> {
  const mode = chooseMode(process.argv.slice(2));
  if (windowsExe && (mode.kind !== 'app' || mode.noOpen)) {
    await showFatalMessage(STANDALONE_ARGS_MESSAGE);
    return 2;
  }
  if (mode.kind === 'help') {
    console.log(MAIN_HELP);
    return 0;
  }
  if (mode.kind === 'app') {
    let windowHost: string | undefined;
    try {
      windowHost = resolveWindowHost(mode.windowHost);
    } catch {
      await showFatalMessage(HOST_INSTALL_FAILED_MESSAGE);
      return 1;
    }
    hostExe = windowHost;
    const quietPrint = windowHost !== undefined && windowsExe; // exe 版には表示先（黒い画面）がない
    return runApp({
      print: (m) => (quietPrint ? undefined : console.log(m)),
      createNonce,
      pickFolder: () => pickFolder(),
      createClient: (token) => createManagementClient({ token }),
      openBrowser,
      touch: () => activity.touch(),
      waitForExit: async (quitRequested) => {
        if (windowHost) {
          // 専用ウィンドウの場合は、ウィンドウを閉じるか「終了する」まで（使っている途中で自動終了しない）
          await Promise.race([waitForExit({ idleMs: Number.POSITIVE_INFINITY, lastActivity: () => Date.now(), signals: process }), quitRequested]);
          return;
        }
        const reason = await Promise.race([
          waitForExit({ idleMs: IDLE_EXIT_MINUTES * 60 * 1000, lastActivity: () => activity.lastActivity(), signals: process }),
          quitRequested.then(() => 'quit' as const),
        ]);
        process.stdout.write(
          reason === 'idle'
            ? `\n画面が${IDLE_EXIT_MINUTES}分間使われなかったため、終了しました。もう一度使うときは、同じ方法で起動してください。\n`
            : '\n終了しました。\n',
        );
      },
      now: () => new Date(),
      noOpen: mode.noOpen,
      openWindow: windowHost ? (url) => startWindowHost({ ...hostCommand(windowHost), url }) : undefined,
      onWindowCrashed: () => showFatalMessage(WINDOW_CRASHED_MESSAGE, windowHost ? { host: hostCommand(windowHost) } : {}),
    });
  }
  return runCli({
    argv: mode.argv,
    env: process.env,
    print: (m) => console.log(m),
    printError: (m) => console.error(m),
    ask,
    askSecret,
    createClient: (token) => createManagementClient({ token }),
    startServer: (options) => startReportServer({ ...options, onReportServed: () => activity.touch() }),
    createNonce,
    openBrowser,
    readFile: (path) => readFileSync(path, 'utf8'),
    waitForExit: waitUntilDone,
    idleExitMinutes: IDLE_EXIT_MINUTES,
    now: () => new Date(),
  });
}

main()
  .then((code) => process.exit(code))
  .catch(async (error: unknown) => {
    if (error instanceof Error && error.message === 'cancelled') {
      console.error('\n中断しました。');
      process.exit(130);
    }
    if (process.env.KOUKAI_CHECK_DEBUG) console.error(error);
    if (windowsExe) await showFatalMessage(UNEXPECTED_ERROR_MESSAGE, hostExe ? { host: hostCommand(hostExe) } : {});
    else console.error('\n予期しないエラーが発生しました。GitHub Issues で報告してください。');
    process.exit(1);
  });
