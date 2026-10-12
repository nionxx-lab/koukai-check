// テスト用の「専用ウィンドウ」の代役。native/windows-host/host.cpp と同じ形式で標準入出力をやり取りする。
// 動きは環境変数で決める:
//   FAKE_HOST_MODE      normal（既定）/ no-runtime / crash / close-after-ready
//   FAKE_HOST_PICK      PICK に対して返すフォルダ（"cancel" ならキャンセル）
//   FAKE_HOST_EXTERNAL  READY のあとに「既定のブラウザで開きたい」と頼む URL（| 区切り）
//   FAKE_HOST_LOG       受け取った行を追記するファイル
//   FAKE_HOST_URL_FILE  最初に受け取った URL を書き出すファイル

import { appendFileSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';

const mode = process.env.FAKE_HOST_MODE ?? 'normal';
const send = (line: string) => process.stdout.write(`${line}\n`);
const log = (line: string) => {
  if (process.env.FAKE_HOST_LOG) appendFileSync(process.env.FAKE_HOST_LOG, `${line}\n`);
};

let first = true;
const rl = createInterface({ input: process.stdin });
rl.on('line', (line) => {
  log(line);
  if (first) {
    first = false;
    if (process.env.FAKE_HOST_URL_FILE) writeFileSync(process.env.FAKE_HOST_URL_FILE, line.replace(/^NAVIGATE /, ''));
    if (mode === 'no-runtime') {
      send('NO-RUNTIME');
      send('CLOSED');
      process.exit(0);
    }
    if (mode === 'crash') process.exit(3);
    send('READY');
    for (const url of (process.env.FAKE_HOST_EXTERNAL ?? '').split('|').filter(Boolean)) send(`EXTERNAL ${url}`);
    if (mode === 'close-after-ready') {
      setTimeout(() => {
        send('CLOSED');
        process.exit(0);
      }, 100);
    }
    return;
  }
  if (line === 'PICK') {
    const pick = process.env.FAKE_HOST_PICK ?? 'cancel';
    send(pick === 'cancel' ? 'PICK-CANCELLED' : `PICKED ${pick}`);
  } else if (line === 'QUIT') {
    send('CLOSED');
    process.exit(0);
  }
});
rl.on('close', () => {
  send('CLOSED');
  process.exit(0);
});
