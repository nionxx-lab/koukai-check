// OS 標準の「フォルダを選ぶ」画面を開き、選ばれたフォルダのパスを返す。
// 依存パッケージを増やさないため、各OSに標準で入っているコマンドを使う。
//   Windows: PowerShell + System.Windows.Forms.FolderBrowserDialog
//   macOS:   osascript（choose folder）
//   Linux:   zenity → kdialog（入っていなければ使えない）
// 使えない・キャンセルされた場合は undefined を返し、画面上でパスを貼り付けてもらう。

import { spawn } from 'node:child_process';

export interface PickerCommand {
  command: string;
  args: string[];
}

const PROMPT = 'チェックするアプリのフォルダを選んでください';

/** PowerShell のスクリプト（日本語を安全に渡すため -EncodedCommand で渡す） */
const POWERSHELL_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms
$owner = New-Object System.Windows.Forms.Form -Property @{ TopMost = $true; ShowInTaskbar = $false }
$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
$dialog.Description = '${PROMPT}'
$dialog.ShowNewFolderButton = $false
if ($dialog.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $dialog.SelectedPath }
$owner.Dispose()
`;

export function pickerCommands(platform: NodeJS.Platform): PickerCommand[] {
  if (platform === 'win32') {
    const encoded = Buffer.from(POWERSHELL_SCRIPT, 'utf16le').toString('base64');
    return [{ command: 'powershell.exe', args: ['-NoProfile', '-NonInteractive', '-STA', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded] }];
  }
  if (platform === 'darwin') {
    return [{ command: 'osascript', args: ['-e', `POSIX path of (choose folder with prompt "${PROMPT}")`] }];
  }
  return [
    { command: 'zenity', args: ['--file-selection', '--directory', `--title=${PROMPT}`] },
    { command: 'kdialog', args: ['--getexistingdirectory', '.', '--title', PROMPT] },
  ];
}

export type PickResult = { kind: 'picked'; path: string } | { kind: 'cancelled' } | { kind: 'unavailable' };

function runOne(cmd: PickerCommand, timeoutMs: number): Promise<PickResult> {
  return new Promise((resolve) => {
    let out = '';
    let settled = false;
    const finish = (r: PickResult) => {
      if (!settled) {
        settled = true;
        resolve(r);
      }
    };
    let child;
    try {
      child = spawn(cmd.command, cmd.args, { stdio: ['ignore', 'pipe', 'ignore'], windowsHide: false });
    } catch {
      finish({ kind: 'unavailable' });
      return;
    }
    const timer = setTimeout(() => {
      child.kill();
      finish({ kind: 'cancelled' });
    }, timeoutMs);
    child.stdout?.setEncoding('utf8');
    child.stdout?.on('data', (c: string) => {
      if (out.length < 8192) out += c;
    });
    child.once('error', () => {
      clearTimeout(timer);
      finish({ kind: 'unavailable' });
    });
    child.once('close', (code) => {
      clearTimeout(timer);
      const path = out.replace(/\r?\n$/, '').split(/\r?\n/).pop()?.trim() ?? '';
      if (code === 0 && path) finish({ kind: 'picked', path });
      else finish({ kind: 'cancelled' });
    });
  });
}

/** フォルダ選択画面を開く。最初に起動できたコマンドの結果を返す。 */
export async function pickFolder(platform: NodeJS.Platform = process.platform, timeoutMs = 10 * 60 * 1000): Promise<PickResult> {
  for (const cmd of pickerCommands(platform)) {
    const r = await runOne(cmd, timeoutMs);
    if (r.kind !== 'unavailable') return r;
  }
  return { kind: 'unavailable' };
}
