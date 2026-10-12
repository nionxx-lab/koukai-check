// テスト用：子プロセスを起動し、あとから「Ctrl+C」を送れるようにする（Linux・macOS・Windows 共通）。
//
// ・Linux / macOS：SIGINT を送る（端末で Ctrl+C を押したときと同じ）
// ・Windows：child.kill('SIGINT') はシグナルを送れず、子プロセスを強制終了してしまう（終了処理が走らない）。
//   そこで、子プロセスを専用の（見えない）コンソールの中で起動し、そのコンソールに Ctrl+C のイベント
//   （GenerateConsoleCtrlEvent）を送る。利用者がコンソールで Ctrl+C を押したときと同じ経路で、Node.js では SIGINT として届く。
//   コンソールを分けるのは、テストを動かしているコンソールに Ctrl+C を送らないため。
//   仲立ちは Windows に必ずある PowerShell 5.1 が行い、標準入出力はバイトのまま中継する（文字コードを変えない）。

import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Readable, Writable } from 'node:stream';

export interface Interruptible {
  stdin: Writable;
  stdout: Readable;
  stderr: Readable;
  /**
   * 子プロセスが起動し終えた（Windows では、仲立ちの PowerShell の準備が終わって子プロセスを起動した）。
   * アプリの起動にかかる時間を測るときは、これを待ってから測り始める（仲立ちの準備の時間を含めないため）
   */
  ready: Promise<void>;
  /** 終了コード */
  exited: Promise<number | null>;
  /** Ctrl+C を送る */
  interrupt(): void;
  /** 後片付け（テストの失敗時など）。子プロセスまで含めて強制終了する。終了済みなら何もしない */
  kill(): void;
}

/** Windows のコマンドラインの1引数として、引用符と \ を正しく付ける（CommandLineToArgvW の規則） */
export function quoteWindowsArg(arg: string): string {
  if (arg !== '' && !/[\s"]/.test(arg)) return arg;
  let out = '"';
  let backslashes = 0;
  for (const ch of arg) {
    if (ch === '\\') {
      backslashes++;
      continue;
    }
    if (ch === '"') {
      out += '\\'.repeat(backslashes * 2 + 1) + '"';
    } else {
      out += '\\'.repeat(backslashes) + ch;
    }
    backslashes = 0;
  }
  return `${out}${'\\'.repeat(backslashes * 2)}"`;
}

const WINDOWS_HOST = String.raw`
$ErrorActionPreference = 'Stop'
$spec = $env:KC_INTERRUPTIBLE_SPEC | ConvertFrom-Json
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public static class KcConsole {
  [DllImport("kernel32.dll")] public static extern bool FreeConsole();
  [DllImport("kernel32.dll")] public static extern bool AllocConsole();
  [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
  [DllImport("kernel32.dll")] public static extern bool SetConsoleCtrlHandler(IntPtr h, bool add);
  [DllImport("kernel32.dll")] public static extern bool GenerateConsoleCtrlEvent(uint e, uint g);
}
"@
# テストを動かしているコンソールから離れ、子プロセス専用のコンソールを作る（画面には出さない）
[KcConsole]::FreeConsole() | Out-Null
[KcConsole]::AllocConsole() | Out-Null
[KcConsole]::ShowWindow([KcConsole]::GetConsoleWindow(), 0) | Out-Null
# 親から「Ctrl+C を無視する」設定を受け継いでいても、子プロセスには通常どおり届くようにする
[KcConsole]::SetConsoleCtrlHandler([IntPtr]::Zero, $false) | Out-Null

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $spec.command
$psi.Arguments = $spec.arguments
$psi.WorkingDirectory = $spec.cwd
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.EnvironmentVariables.Clear()
foreach ($p in $spec.env.PSObject.Properties) { $psi.EnvironmentVariables[$p.Name] = [string]$p.Value }
$child = [System.Diagnostics.Process]::Start($psi)
# 子プロセスを起動し終えたことを知らせる
[System.IO.File]::WriteAllText($spec.readyFile, [string]$child.Id)

$out = [Console]::OpenStandardOutput()
$err = [Console]::OpenStandardError()
$in = [Console]::OpenStandardInput()
$copyOut = $child.StandardOutput.BaseStream.CopyToAsync($out)
$copyErr = $child.StandardError.BaseStream.CopyToAsync($err)
$copyIn = $in.CopyToAsync($child.StandardInput.BaseStream)
$stdinClosed = $false
$sent = $false
while (-not $child.HasExited) {
  if (-not $stdinClosed -and $copyIn.IsCompleted) { try { $child.StandardInput.Close() } catch {} ; $stdinClosed = $true }
  if (-not $sent -and (Test-Path -LiteralPath $spec.controlFile)) {
    # この仲立ち自身は Ctrl+C を無視し、同じコンソールの子プロセスにだけ効かせる
    [KcConsole]::SetConsoleCtrlHandler([IntPtr]::Zero, $true) | Out-Null
    [KcConsole]::GenerateConsoleCtrlEvent(0, 0) | Out-Null
    $sent = $true
  }
  Start-Sleep -Milliseconds 20
}
$child.WaitForExit()
[System.Threading.Tasks.Task]::WaitAll(@($copyOut, $copyErr), 10000) | Out-Null
$out.Flush()
$err.Flush()
exit $child.ExitCode
`;

/**
 * 子プロセスを起動する。interruptible: false なら、Ctrl+C を送らない（どのOSでもそのまま起動する。仲立ちを使わないので速い）
 */
export function spawnInterruptible(
  command: string,
  args: string[],
  options: { cwd?: string; env?: NodeJS.ProcessEnv; interruptible?: boolean } = {},
): Interruptible {
  const env = options.env ?? process.env;
  if (process.platform !== 'win32' || options.interruptible === false) {
    const child = spawn(command, args, { cwd: options.cwd, env, stdio: ['pipe', 'pipe', 'pipe'] });
    return wrap(child, Promise.resolve(), () => child.kill('SIGINT'), () => child.kill('SIGKILL'));
  }
  const control = mkdtempSync(join(tmpdir(), 'kc-ctrlc-'));
  const controlFile = join(control, 'interrupt');
  const readyFile = join(control, 'ready');
  const spec = {
    command,
    arguments: args.map(quoteWindowsArg).join(' '),
    cwd: options.cwd ?? process.cwd(),
    env: Object.fromEntries(Object.entries(env).filter((e): e is [string, string] => typeof e[1] === 'string')),
    controlFile,
    readyFile,
  };
  const child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', Buffer.from(WINDOWS_HOST, 'utf16le').toString('base64')], {
    // 仲立ちはテストと同じ環境で動かす（子プロセスの環境は spec で渡す）。作業用のファイルを子プロセスの環境に作らないため
    env: { ...process.env, KC_INTERRUPTIBLE_SPEC: JSON.stringify(spec) },
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
  });
  let done = false;
  child.once('exit', () => {
    done = true;
    rmSync(control, { recursive: true, force: true });
  });
  // 仲立ちが子プロセスを起動し終えるまで待つ（仲立ちが先に終わったら失敗）
  const ready = new Promise<void>((resolve, reject) => {
    const timer = setInterval(() => {
      if (existsSync(readyFile)) {
        clearInterval(timer);
        resolve();
      } else if (done) {
        clearInterval(timer);
        reject(new Error('子プロセスを起動する前に、仲立ち（PowerShell）が終了しました'));
      }
    }, 20);
  });
  // taskkill /T：仲立ちと、その子プロセス（別のコンソールの node）をまとめて終了する
  const killTree = () => {
    if (!done && child.pid !== undefined) spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
  };
  return wrap(child, ready, () => writeFileSync(controlFile, ''), killTree);
}

function wrap(child: ChildProcess, ready: Promise<void>, interrupt: () => void, kill: () => void): Interruptible {
  if (!child.stdin || !child.stdout || !child.stderr) throw new Error('標準入出力を開けませんでした');
  let exitedFlag = false;
  const exited = new Promise<number | null>((resolve) =>
    child.once('exit', (code) => {
      exitedFlag = true;
      resolve(code);
    }),
  );
  return {
    stdin: child.stdin,
    stdout: child.stdout,
    stderr: child.stderr,
    ready,
    exited,
    interrupt,
    kill: () => {
      if (!exitedFlag) kill();
    },
  };
}

/**
 * Windows で子プロセスを動かすのに欠かせない環境変数（テストで環境を絞るときに足す）。
 * SystemRoot などがないと、Windows の Node.js はネットワークや乱数の初期化に失敗することがある。実際の Windows には必ずある値。
 */
export function windowsBaseEnv(): Record<string, string> {
  if (process.platform !== 'win32') return {};
  const out: Record<string, string> = {};
  for (const name of ['SystemRoot', 'SystemDrive', 'windir', 'ComSpec', 'PATHEXT', 'OS']) {
    const value = Object.entries(process.env).find(([k]) => k.toLowerCase() === name.toLowerCase())?.[1];
    if (value) out[name] = value;
  }
  return out;
}
