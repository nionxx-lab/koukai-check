// 既定のブラウザでURLを開く。依存パッケージを増やさないため、OS標準のコマンドを使う。
// URL は自分で組み立てた http://127.0.0.1:<port>/r/<hex> だけを渡す（シェルは経由しない）。

import { spawn } from 'node:child_process';
import { platform } from 'node:process';

export function openBrowser(url: string): Promise<boolean> {
  if (!/^http:\/\/127\.0\.0\.1:\d+\/r\/[0-9a-f]+\/?$/.test(url)) return Promise.resolve(false);

  let command: string;
  let args: string[];
  if (platform === 'darwin') {
    command = 'open';
    args = [url];
  } else if (platform === 'win32') {
    // start の第1引数はウィンドウタイトル（空文字）。URL に & 等は含まれない
    command = 'cmd';
    args = ['/c', 'start', '', url];
  } else {
    command = 'xdg-open';
    args = [url];
  }

  return new Promise((resolve) => {
    try {
      const child = spawn(command, args, { stdio: 'ignore', detached: true, windowsHide: true });
      child.once('error', () => resolve(false));
      child.once('spawn', () => {
        child.unref();
        resolve(true);
      });
    } catch {
      resolve(false);
    }
  });
}
