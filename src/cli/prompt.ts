import { createInterface } from 'node:readline/promises';
import process, { stdin, stdout } from 'node:process';

// TTY でない場合（パイプ入力など）は、1つの readline を使い回して行を順に読む。
// 呼び出しごとに作り直すと、先に読み込まれた残りの行が失われるため。
let pipedLines: AsyncIterator<string> | undefined;

async function askPiped(question: string): Promise<string> {
  stdout.write(question);
  pipedLines ??= createInterface({ input: stdin, terminal: false })[Symbol.asyncIterator]();
  const next = await pipedLines.next();
  if (next.done) throw new Error('cancelled');
  stdout.write('\n');
  return next.value.trim();
}

export async function ask(question: string): Promise<string> {
  if (!stdin.isTTY) return askPiped(question);
  const rl = createInterface({ input: stdin, output: stdout });
  const abort = new AbortController();
  // 入力待ちで Ctrl+C を押したら中断として扱う（readline は既定では SIGINT を握りつぶすため）
  rl.on('SIGINT', () => abort.abort());
  try {
    return (await rl.question(question, { signal: abort.signal })).trim();
  } catch (error) {
    if (abort.signal.aborted) throw new Error('cancelled');
    throw error;
  } finally {
    rl.close();
  }
}

// ───────────── トークンの非表示入力 ─────────────
//
// 端末を raw モードにして1文字ずつ受け取り、画面には何も表示しない（エコーしない）。
// Windows Terminal / PowerShell / cmd.exe / macOS Terminal / Linux の端末で、Node.js の raw モードは同じように動く。
// ・Backspace は 0x7f（多くの端末）と 0x08（Windows の一部）の両方を扱う
// ・矢印キー等のエスケープシーケンス、その他の制御文字は無視する（トークンに混入させない）
// ・貼り付けは1回の data イベントにまとまって届くことがあるため、チャンク単位で処理する
// ・日本語IMEがオンでも、確定した文字が届くだけで表示はしない（トークンは英数字のため通常は影響しない）

export type SecretKeyResult = { kind: 'continue'; value: string } | { kind: 'submit'; value: string } | { kind: 'cancel' };

const ZERO_WIDTH = /[\u200b-\u200d\u2060\ufeff]/g;

/** raw モードで受け取った文字列を処理する（副作用なし。テスト用に公開）。 */
export function processSecretChunk(current: string, chunk: string): SecretKeyResult {
  let value = current;
  // ESC [ ... 終端文字 / ESC O x などのエスケープシーケンスを取り除く（矢印キー・ブラケットペーストの印など）
  const text = chunk.replace(/\u001b\[[0-9;?]*[ -\/]*[@-~]/g, '').replace(/\u001b[O]?[\s\S]?/g, '');
  for (const ch of text) {
    if (ch === '\r' || ch === '\n') return { kind: 'submit', value: value.replace(ZERO_WIDTH, '').trim() };
    if (ch === '\u0003') return { kind: 'cancel' }; // Ctrl+C
    if (ch === '\u0004') {
      // Ctrl+D: 空なら中断、入力済みなら確定
      return value.length === 0 ? { kind: 'cancel' } : { kind: 'submit', value: value.replace(ZERO_WIDTH, '').trim() };
    }
    if (ch === '\u007f' || ch === '\b') {
      value = Array.from(value).slice(0, -1).join('');
      continue;
    }
    if (ch === '\u0015') {
      value = ''; // Ctrl+U: 入力を消す
      continue;
    }
    const code = ch.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) continue; // その他の制御文字は無視
    value += ch;
  }
  return { kind: 'continue', value };
}

let rawModeActive = false;
// 想定外の終了でも、端末を raw モードのまま残さない
process.once('exit', () => {
  if (rawModeActive && stdin.isTTY) stdin.setRawMode(false);
});

/**
 * 文字を隠した入力ができない「対話的な端末」の可能性を判定する（副作用なし。テスト用に公開）。
 * Windows の Git Bash（mintty）などは標準入力が TTY にならず raw モードを使えないため、
 * 端末側が入力した文字をそのまま表示してしまうことがある。
 */
export function secretInputWarning(env: Record<string, string | undefined>, platform: string, stdinIsTTY: boolean): string | undefined {
  if (stdinIsTTY) return undefined;
  const looksLikeMintty = platform === 'win32' && (env.MSYSTEM !== undefined || env.TERM_PROGRAM === 'mintty' || env.TERM === 'xterm');
  if (!looksLikeMintty) return undefined;
  return [
    '⚠ この端末（Git Bash など）では、入力したトークンが画面に表示される可能性があります。',
    '  PowerShell か Windows Terminal で実行するか、Git Bash では「winpty npx koukai-check」で実行してください。',
    '  そのまま続ける場合は、周りから画面が見えないことを確認してください。',
  ].join('\n');
}

/** 入力内容を画面に表示せずに1行読む（トークン入力用）。TTYでない場合はエコーのないパイプから読む。 */
export async function askSecret(question: string): Promise<string> {
  if (!stdin.isTTY) {
    const warning = secretInputWarning(process.env, process.platform, false);
    if (warning) stdout.write(`${warning}\n`);
    return askPiped(question);
  }

  stdout.write(question);
  stdin.setRawMode(true);
  rawModeActive = true;
  stdin.resume();
  stdin.setEncoding('utf8');

  return new Promise((resolve, reject) => {
    let value = '';
    const onData = (chunk: string) => {
      const result = processSecretChunk(value, chunk);
      if (result.kind === 'continue') {
        value = result.value;
        return;
      }
      cleanup();
      stdout.write('\n');
      if (result.kind === 'submit') resolve(result.value);
      else reject(new Error('cancelled'));
    };
    const cleanup = () => {
      stdin.off('data', onData);
      stdin.setRawMode(false);
      rawModeActive = false;
      stdin.pause();
      value = '';
    };
    stdin.on('data', onData);
  });
}
