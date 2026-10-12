// 配布用の単一実行ファイル（Windows の .exe。Node.js SEA）として起動されたかどうか。
// Windows の exe 版は「ウィンドウのアプリ」として作ってあり、黒い画面（コンソール）は開かない。
// 画面は専用ウィンドウ（WebView2）に表示する（src/app/window-host.ts）。

import { getAsset, isSea } from 'node:sea';
import { Writable } from 'node:stream';

export function isStandaloneExe(): boolean {
  try {
    return isSea();
  } catch {
    return false;
  }
}

/**
 * 黒い画面のない exe では、標準出力・標準エラーが無効なハンドルのことがある。
 * そのままだと、使った瞬間（Node.js の内部で触れた場合も含む）に例外や 'error' が起きて落ちるため、
 * 書き込めなくても何もしない出力に差し替える。
 */
export function guardStdio(target: NodeJS.Process = process): void {
  for (const name of ['stdout', 'stderr'] as const) {
    try {
      target[name].on('error', () => undefined);
    } catch {
      const sink = new Writable({ write: (_chunk, _enc, cb) => cb() });
      Object.defineProperty(target, name, { configurable: true, enumerable: true, get: () => sink });
    }
  }
}

/** exe の中に入れた部品を読む（SEA の assets） */
export function readStandaloneAsset(key: string): ArrayBuffer {
  return getAsset(key);
}

/** exe 版に引数を付けて起動されたとき（開発用のCLIは exe 版では使えない。画面がないため） */
export const STANDALONE_ARGS_MESSAGE = [
  'この exe は、ダブルクリックで起動して使います（引数は使えません）。',
  '',
  'ターミナルで Supabase の診断だけを行う開発者向けの機能は、Node.js 22 以上を入れたうえで',
  '  npx koukai-check supabase',
  'として使ってください。',
].join('\n');

export const UNEXPECTED_ERROR_MESSAGE = '予期しないエラーが発生したため、公開前チェックを終了しました。\nもう一度起動しても直らない場合は、GitHub Issues で報告してください。';

export const WINDOW_CRASHED_MESSAGE =
  '画面（専用ウィンドウ）が予期せず終了したため、公開前チェックを終了しました。\nもう一度起動しても直らない場合は、GitHub Issues で報告してください。';

export const HOST_INSTALL_FAILED_MESSAGE =
  '画面を表示するための部品を準備できませんでした。\n\nウイルス対策ソフトがファイルを止めている可能性があります。もう一度起動しても直らない場合は、GitHub Issues で報告してください。';
