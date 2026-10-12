#!/usr/bin/env node
// アプリのアイコン（native/windows-host/icon.ico）を作る。画像ファイルや外部ツールを使わず、図形を計算で描く。
//   node scripts/make-icon.mjs
// 図柄：角の丸い緑の四角に、白いチェックマーク。

import { writeFileSync } from 'node:fs';
import { deflateSync } from 'node:zlib';

const SIZES = [16, 24, 32, 48, 64, 128, 256];
const SS = 4; // なめらかにするための拡大描画の倍率

function distToSegment(px, py, ax, ay, bx, by) {
  const dx = bx - ax;
  const dy = by - ay;
  const t = Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
}

/** 0〜1 の座標で、その点の色 [r,g,b,a] を返す */
function shade(x, y) {
  const r = 0.2; // 角の丸み
  const m = 0.04; // 余白
  const cx = Math.min(Math.max(x, m + r), 1 - m - r);
  const cy = Math.min(Math.max(y, m + r), 1 - m - r);
  if (Math.hypot(x - cx, y - cy) > r) return [0, 0, 0, 0];
  const d = Math.min(distToSegment(x, y, 0.27, 0.52, 0.44, 0.69), distToSegment(x, y, 0.44, 0.69, 0.75, 0.33));
  if (d < 0.075) return [255, 255, 255, 255];
  const g = y; // 上から下へ少し濃くする
  return [Math.round(24 - 8 * g), Math.round(140 - 30 * g), Math.round(98 - 20 * g), 255];
}

function render(size) {
  const px = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let r = 0, g = 0, b = 0, a = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const [cr, cg, cb, ca] = shade((x + (sx + 0.5) / SS) / size, (y + (sy + 0.5) / SS) / size);
          r += cr * ca;
          g += cg * ca;
          b += cb * ca;
          a += ca;
        }
      }
      const i = (y * size + x) * 4;
      px[i] = a ? Math.round(r / a) : 0;
      px[i + 1] = a ? Math.round(g / a) : 0;
      px[i + 2] = a ? Math.round(b / a) : 0;
      px[i + 3] = Math.round(a / (SS * SS));
    }
  }
  return px;
}

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(buf) {
  let c = 0xffffffff;
  for (const byte of buf) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}
function png(size, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // 8bit
  ihdr[9] = 6; // RGBA
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0))]);
}

/** PNG を並べた .ico（Windows Vista 以降が対応） */
export function buildIco() {
  const images = SIZES.map((s) => png(s, render(s)));
  const header = Buffer.alloc(6 + 16 * SIZES.length);
  header.writeUInt16LE(1, 2); // アイコン
  header.writeUInt16LE(SIZES.length, 4);
  let offset = header.length;
  SIZES.forEach((s, i) => {
    const e = 6 + 16 * i;
    header[e] = s >= 256 ? 0 : s;
    header[e + 1] = s >= 256 ? 0 : s;
    header.writeUInt16LE(1, e + 4); // planes
    header.writeUInt16LE(32, e + 6); // bpp
    header.writeUInt32LE(images[i].length, e + 8);
    header.writeUInt32LE(offset, e + 12);
    offset += images[i].length;
  });
  return Buffer.concat([header, ...images]);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const out = new URL('../native/windows-host/icon.ico', import.meta.url);
  writeFileSync(out, buildIco());
  console.log(`作成しました: ${out.pathname}`);
}
