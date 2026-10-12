// テスト用の「Ctrl+C を送れる子プロセス」（test/helpers/interruptible.ts）自体のテスト。
// Ctrl+C が SIGINT として届くこと、後片付けで子プロセスが残らないことを、どの OS でも確かめる。

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { quoteWindowsArg, spawnInterruptible } from './helpers/interruptible.js';

/** 子プロセスで動かすスクリプト：自分の pid を出し、SIGINT を受けたら「got SIGINT」と出して終了コード 0 で終わる */
const CHILD = `
process.on('SIGINT', () => { process.stdout.write('got SIGINT\\n'); process.exit(0); });
process.stdout.write('pid ' + process.pid + '\\n');
setInterval(() => {}, 1000);
`;

function readUntil(stream: NodeJS.ReadableStream, re: RegExp, timeoutMs = 15_000): Promise<RegExpMatchArray> {
  let out = '';
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timeout: ${out}`)), timeoutMs);
    stream.on('data', (c: Buffer) => {
      out += c.toString();
      const m = out.match(re);
      if (m) {
        clearTimeout(timer);
        resolve(m);
      }
    });
  });
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

describe('Ctrl+C を送れる子プロセス（テスト用）', { timeout: 120_000 }, () => {
  it('Ctrl+C は、子プロセスに SIGINT として届き、終了処理が走る（終了コード 0）', async () => {
    const child = spawnInterruptible(process.execPath, ['-e', CHILD]);
    try {
      child.stdin.end();
      await child.ready;
      const got = readUntil(child.stdout, /got SIGINT/);
      await readUntil(child.stdout, /pid \d+/);
      child.interrupt();
      await got;
      assert.equal(await child.exited, 0);
    } finally {
      child.kill();
    }
  });

  it('後片付け（kill）で、子プロセスまで終了する（Windows では仲立ちの先の node も残らない）', async () => {
    const child = spawnInterruptible(process.execPath, ['-e', CHILD]);
    child.stdin.end();
    await child.ready;
    const pid = Number((await readUntil(child.stdout, /pid (\d+)/))[1]);
    assert.ok(alive(pid));
    child.kill();
    await child.exited;
    for (let i = 0; i < 100 && alive(pid); i++) await new Promise((r) => setTimeout(r, 50));
    assert.equal(alive(pid), false, '子プロセスが残っている');
  });

  it('Windows のコマンドラインの引数は、空白・引用符・\\ を正しく包む', () => {
    assert.equal(quoteWindowsArg('abc'), 'abc');
    assert.equal(quoteWindowsArg('a b'), '"a b"');
    assert.equal(quoteWindowsArg(''), '""');
    assert.equal(quoteWindowsArg('say "hi"'), '"say \\"hi\\""');
    assert.equal(quoteWindowsArg('C:\\dir with space\\'), '"C:\\dir with space\\\\"');
    assert.equal(quoteWindowsArg('a\\\\"b'), '"a\\\\\\\\\\"b"');
  });
});
