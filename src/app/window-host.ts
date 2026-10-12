// Windows の専用ウィンドウ（native/windows-host/host.cpp）を起動し、標準入出力でやり取りする。
//
// 専用ウィンドウは WebView2 で 127.0.0.1 の画面だけを表示する。ここ（Node.js 側）が担当するのは:
//   ・最初に表示する URL を渡す（コマンドライン引数ではなく標準入力で渡す）
//   ・「フォルダを選ぶ」を頼み、結果を受け取る（フォルダ選択の画面は、専用ウィンドウを親にして表示される）
//   ・リンクを既定のブラウザで開いてよいかの判定（許可したものだけ OPEN-EXTERNAL で返す）
//   ・終了の指示（QUIT）と、ウィンドウが閉じられたことの検知
// やり取りは1行ずつの UTF-8 テキスト。形式は host.cpp の先頭のコメントを参照。

import { spawn, type ChildProcess } from 'node:child_process';
import { isAllowedExternalUrl } from '../shared/url.js';
import type { PickResult } from './folder-picker.js';

export type HostMessage =
  | { kind: 'ready' }
  | { kind: 'picked'; path: string }
  | { kind: 'pick-cancelled' }
  | { kind: 'pick-failed' }
  | { kind: 'external'; url: string }
  | { kind: 'no-runtime' }
  | { kind: 'failed'; code: string }
  | { kind: 'closed' };

const MAX_LINE = 16 * 1024;

/** 専用ウィンドウから届いた1行を解釈する。知らない形式は undefined（無視する） */
export function parseHostLine(raw: string): HostMessage | undefined {
  const line = raw.replace(/\r$/, '');
  if (line.length > MAX_LINE) return undefined;
  const space = line.indexOf(' ');
  const head = space < 0 ? line : line.slice(0, space);
  const rest = space < 0 ? '' : line.slice(space + 1);
  switch (head) {
    case 'READY':
      return { kind: 'ready' };
    case 'PICKED':
      return rest ? { kind: 'picked', path: rest } : { kind: 'pick-failed' };
    case 'PICK-CANCELLED':
      return { kind: 'pick-cancelled' };
    case 'PICK-FAILED':
      return { kind: 'pick-failed' };
    case 'EXTERNAL':
      return { kind: 'external', url: rest };
    case 'NO-RUNTIME':
      return { kind: 'no-runtime' };
    case 'FAILED':
      return { kind: 'failed', code: rest.slice(0, 64) };
    case 'CLOSED':
      return { kind: 'closed' };
    default:
      return undefined;
  }
}

export type HostCommand = { kind: 'navigate'; url: string } | { kind: 'pick' } | { kind: 'open-external'; url: string } | { kind: 'quit' };

/** 専用ウィンドウへ送る1行。改行を含む値は送らない（1行の区切りが崩れるため） */
export function formatHostCommand(cmd: HostCommand): string {
  const line =
    cmd.kind === 'navigate' ? `NAVIGATE ${cmd.url}` : cmd.kind === 'open-external' ? `OPEN-EXTERNAL ${cmd.url}` : cmd.kind === 'pick' ? 'PICK' : 'QUIT';
  if (/[\r\n]/.test(line)) throw new Error('改行を含む指示は送れません');
  return `${line}\n`;
}

/** 専用ウィンドウが終わった理由 */
export type HostExit =
  | { kind: 'closed' } // 利用者がウィンドウを閉じた、または QUIT で閉じた
  | { kind: 'no-runtime' } // WebView2 ランタイムがない（案内はウィンドウ側で表示済み）
  | { kind: 'failed'; code: string } // 起動・表示に失敗した（案内はウィンドウ側で表示済み）
  | { kind: 'crashed' }; // 何も言わずに終了した、または起動できなかった

export interface WindowHost {
  /** ウィンドウが表示され、画面の読み込みを始めた */
  ready: Promise<void>;
  /** ウィンドウが終わったとき */
  exited: Promise<HostExit>;
  pickFolder(): Promise<PickResult>;
  /** ウィンドウを閉じて、終わるまで待つ */
  close(timeoutMs?: number): Promise<void>;
}

export interface StartWindowHostOptions {
  command: string;
  args?: string[];
  /** 表示する画面（http://127.0.0.1:<port>/r/<乱数>/） */
  url: string;
  /** テスト用 */
  spawnImpl?: typeof spawn;
  /** 既定のブラウザで開くことを許可したとき（記録用） */
  onExternalOpened?(url: string): void;
}

const APP_URL = /^http:\/\/127\.0\.0\.1:\d{1,5}\/r\/[0-9a-f]{32}\/$/;

export function startWindowHost(options: StartWindowHostOptions): WindowHost {
  if (!APP_URL.test(options.url)) throw new Error('専用ウィンドウに渡せない URL です');
  const spawnImpl = options.spawnImpl ?? spawn;

  let child: ChildProcess;
  let resolveReady: () => void = () => undefined;
  const ready = new Promise<void>((r) => (resolveReady = r));
  let resolveExited: (e: HostExit) => void = () => undefined;
  const exited = new Promise<HostExit>((r) => (resolveExited = r));
  let exitReason: HostExit | undefined;
  let pendingPick: ((r: PickResult) => void) | undefined;
  let pickPromise: Promise<PickResult> | undefined;
  let finished = false;

  const finish = () => {
    if (finished) return;
    finished = true;
    pendingPick?.({ kind: 'cancelled' });
    pendingPick = undefined;
    resolveExited(exitReason ?? { kind: 'crashed' });
  };

  const write = (cmd: HostCommand) => {
    if (finished || !child.stdin || child.stdin.destroyed) return;
    child.stdin.write(formatHostCommand(cmd));
  };

  const onMessage = (m: HostMessage) => {
    switch (m.kind) {
      case 'ready':
        resolveReady();
        return;
      case 'picked':
      case 'pick-cancelled':
      case 'pick-failed': {
        const done = pendingPick;
        pendingPick = undefined;
        done?.(m.kind === 'picked' ? { kind: 'picked', path: m.path } : m.kind === 'pick-cancelled' ? { kind: 'cancelled' } : { kind: 'unavailable' });
        return;
      }
      case 'external':
        if (isAllowedExternalUrl(m.url)) {
          write({ kind: 'open-external', url: m.url });
          options.onExternalOpened?.(m.url);
        }
        return;
      case 'no-runtime':
        exitReason = { kind: 'no-runtime' };
        return;
      case 'failed':
        exitReason = { kind: 'failed', code: m.code };
        return;
      case 'closed':
        exitReason ??= { kind: 'closed' };
        return;
    }
  };

  try {
    // windowsHide は付けない（付けると、最初に表示するウィンドウまで隠れてしまう）
    child = spawnImpl(options.command, options.args ?? [], { stdio: ['pipe', 'pipe', 'ignore'], windowsHide: false });
  } catch {
    finish();
    return { ready, exited, pickFolder: async () => ({ kind: 'unavailable' }), close: async () => undefined };
  }

  let buffer = '';
  child.stdout?.setEncoding('utf8');
  child.stdout?.on('data', (chunk: string) => {
    buffer += chunk;
    let nl: number;
    while ((nl = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, nl);
      buffer = buffer.slice(nl + 1);
      const m = parseHostLine(line);
      if (m) onMessage(m);
    }
    if (buffer.length > MAX_LINE) buffer = ''; // 改行のない長すぎる出力は捨てる
  });
  child.stdin?.on('error', () => undefined); // ウィンドウ側が先に終わっていても落ちない
  child.once('error', finish);
  child.once('exit', finish);

  write({ kind: 'navigate', url: options.url });

  return {
    ready,
    exited,
    pickFolder() {
      if (finished) return Promise.resolve({ kind: 'unavailable' });
      // 同時に2回頼まれても、フォルダ選択の画面は1つだけ（同じ結果を返す）
      if (pickPromise) return pickPromise;
      pickPromise = new Promise<PickResult>((resolve) => {
        pendingPick = resolve;
        write({ kind: 'pick' });
      }).finally(() => {
        pickPromise = undefined;
      });
      return pickPromise;
    },
    async close(timeoutMs = 5000) {
      if (finished) return;
      write({ kind: 'quit' });
      child.stdin?.end();
      const timer = setTimeout(() => child.kill(), timeoutMs);
      await exited;
      clearTimeout(timer);
    },
  };
}
