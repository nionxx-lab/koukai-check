// 予期しないエラーを、利用者に見える形で知らせる。
// Windows の exe 版には黒い画面（コンソール）がないため、メッセージボックスで表示する。
//   1. 専用ウィンドウの部品があれば、それで表示する（koukai-check-window.exe --fatal）
//   2. なければ、Windows 標準の PowerShell で表示する
// それ以外の OS では、ターミナルに表示する。

import { spawn } from 'node:child_process';

function run(command: string, args: string[], input?: string, timeoutMs = 10 * 60 * 1000): Promise<boolean> {
  return new Promise((resolve) => {
    try {
      const child = spawn(command, args, { stdio: [input === undefined ? 'ignore' : 'pipe', 'ignore', 'ignore'], windowsHide: input === undefined });
      const timer = setTimeout(() => child.kill(), timeoutMs);
      child.once('error', () => {
        clearTimeout(timer);
        resolve(false);
      });
      child.once('exit', (code) => {
        clearTimeout(timer);
        resolve(code === 0);
      });
      if (input !== undefined) {
        child.stdin?.on('error', () => undefined);
        child.stdin?.end(input);
      }
    } catch {
      resolve(false);
    }
  });
}

/** PowerShell でメッセージボックスを出すスクリプト。文章は Base64 にして埋め込む（引用符などで崩れない） */
export function powershellMessageBoxScript(message: string): string {
  const b64 = Buffer.from(message, 'utf8').toString('base64');
  return [
    'Add-Type -AssemblyName System.Windows.Forms',
    `$m = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('${b64}'))`,
    "[void][System.Windows.Forms.MessageBox]::Show($m, '公開前チェック', 'OK', 'Error')",
  ].join('\n');
}

export async function showFatalMessage(
  message: string,
  options: { platform?: NodeJS.Platform; host?: { command: string; args: string[] }; printError?: (m: string) => void } = {},
): Promise<void> {
  const platform = options.platform ?? process.platform;
  if (platform !== 'win32') {
    (options.printError ?? ((m) => console.error(m)))(message);
    return;
  }
  if (options.host && (await run(options.host.command, [...options.host.args, '--fatal'], message))) return;
  const encoded = Buffer.from(powershellMessageBoxScript(message), 'utf16le').toString('base64');
  await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-STA', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded]);
}
