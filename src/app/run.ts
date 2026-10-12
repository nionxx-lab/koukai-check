// 一般ユーザー向けの入口：「フォルダを選ぶ」画面を開く。
//   ・Windows の exe 版：専用ウィンドウ（WebView2）の中に表示する。ブラウザもターミナルも使わない
//   ・npx で起動した場合：既定のブラウザで開く。ターミナルに表示するのは、URLと終了方法だけ

import type { ManagementClient } from '../supabase/client.js';
import type { PickResult } from './folder-picker.js';
import { startAppServer } from './server.js';
import type { HostExit, WindowHost } from './window-host.js';

export interface AppRunDeps {
  print(message: string): void;
  createNonce(): string;
  pickFolder(): Promise<PickResult>;
  createClient(token: string): Pick<ManagementClient, 'getSecurityAdvisors'>;
  openBrowser(url: string): Promise<boolean>;
  /** 画面が表示されたことを知らせる（自動終了までの時間を延ばす） */
  touch(): void;
  /** Ctrl+C・一定時間の無操作・画面の「終了する」（quitRequested）のいずれかまで待つ */
  waitForExit(quitRequested: Promise<void>): Promise<void>;
  now(): Date;
  noOpen?: boolean;
  /** 専用ウィンドウで表示する場合に指定する（指定しなければ既定のブラウザで開く） */
  openWindow?(url: string): WindowHost;
  /** 専用ウィンドウが、案内を出さずに終わってしまったとき */
  onWindowCrashed?(): Promise<void>;
}

export async function runApp(deps: AppRunDeps): Promise<number> {
  let resolveQuit: () => void = () => undefined;
  const quitRequested = new Promise<void>((r) => (resolveQuit = r));
  let host: WindowHost | undefined;

  const server = await startAppServer({
    nonce: deps.createNonce(),
    // 専用ウィンドウがあれば、フォルダ選択の画面はそのウィンドウを親にして出してもらう
    pickFolder: () => (host ? host.pickFolder() : deps.pickFolder()),
    createClient: deps.createClient,
    now: deps.now,
    onActivity: () => deps.touch(),
    onQuit: () => resolveQuit(),
  });

  if (deps.openWindow) return runInWindow(deps, deps.openWindow, server, quitRequested, (h) => (host = h));

  deps.print('公開前チェック');
  deps.print('AIで作ったアプリを公開する前に、危ない設定がないか確認します。');
  const opened = deps.noOpen ? false : await deps.openBrowser(server.url);
  deps.print(opened ? 'ブラウザで画面を開きました。' : '次のURLをブラウザで開いてください。');
  deps.print(server.url);
  deps.print('使い終わったら、画面の「終了する」を押すか、このウィンドウで Ctrl+C を押してください。');

  try {
    await deps.waitForExit(quitRequested);
  } finally {
    await server.close();
  }
  return 0;
}

/** 専用ウィンドウで表示する。ウィンドウを閉じる・「終了する」・Ctrl+C のどれでも、ウィンドウとサーバーを止めて終わる */
async function runInWindow(
  deps: AppRunDeps,
  openWindow: (url: string) => WindowHost,
  server: { url: string; close(): Promise<void> },
  quitRequested: Promise<void>,
  setHost: (h: WindowHost) => void,
): Promise<number> {
  let exit: HostExit | undefined;
  try {
    const host = openWindow(server.url);
    setHost(host);
    const windowClosed = host.exited.then((e) => {
      exit = e;
    });
    try {
      await deps.waitForExit(Promise.race([quitRequested, windowClosed]));
    } finally {
      await host.close();
    }
    exit ??= await host.exited;
  } finally {
    await server.close();
  }
  if (exit?.kind === 'closed') return 0;
  if (exit?.kind === 'crashed') await deps.onWindowCrashed?.();
  return 1;
}
