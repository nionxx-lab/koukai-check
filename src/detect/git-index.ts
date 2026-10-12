// Git の index（.git/index）から、Git が管理しているファイルの一覧を読む（読み取りのみ。git コマンドは使わない）。
// .gitignore に書かれていても、すでにコミットしたファイルは Git の管理対象のまま（公開される）ため、
// 「Git に入っているか」は .gitignore ではなく index で判定する。
//
// 対応：index の形式 2・3・4。読めない形式・大きすぎる場合は undefined（.gitignore だけで判定する）。

import { readFileSync, statSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';

const MAX_INDEX_BYTES = 64 * 1024 * 1024;

/** .git がファイル（worktree・submodule）の場合は、指している先を返す */
function gitDir(gitRoot: string): string | undefined {
  const dotGit = join(gitRoot, '.git');
  try {
    const st = statSync(dotGit);
    if (st.isDirectory()) return dotGit;
    const m = /^gitdir:\s*(.+)\s*$/m.exec(readFileSync(dotGit, 'utf8'));
    if (!m?.[1]) return undefined;
    return isAbsolute(m[1]) ? m[1] : resolve(dirname(dotGit), m[1]);
  } catch {
    return undefined;
  }
}

/** index を読み、管理されているファイルのパス（リポジトリのルートからの相対パス、区切りは /）を返す */
export function readGitIndex(gitRoot: string): Set<string> | undefined {
  const dir = gitDir(gitRoot);
  if (!dir) return undefined;
  let buf: Buffer;
  try {
    const path = join(dir, 'index');
    if (statSync(path).size > MAX_INDEX_BYTES) return undefined;
    buf = readFileSync(path);
  } catch (error) {
    // index がない＝まだ何も追加していない（git init の直後など）
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return new Set();
    return undefined;
  }
  try {
    return parseGitIndex(buf);
  } catch {
    return undefined;
  }
}

export function parseGitIndex(buf: Buffer): Set<string> | undefined {
  if (buf.length < 12 || buf.toString('latin1', 0, 4) !== 'DIRC') return undefined;
  const version = buf.readUInt32BE(4);
  if (version < 2 || version > 4) return undefined;
  const count = buf.readUInt32BE(8);
  const paths = new Set<string>();
  let p = 12;
  let previous: Buffer = Buffer.alloc(0); // 形式4の圧縮はバイト単位（日本語のパスで文字数とずれないように）
  for (let n = 0; n < count; n++) {
    const start = p;
    if (p + 62 > buf.length) return undefined;
    const flags = buf.readUInt16BE(p + 60);
    p += 62;
    if (version >= 3 && flags & 0x4000) p += 2; // 拡張フラグ
    let name: string;
    if (version === 4) {
      // 前のパスの末尾から何バイト消すか（可変長の整数）＋ 残りの部分
      let strip = 0;
      let byte = buf[p++] ?? 0;
      strip = byte & 0x7f;
      while (byte & 0x80) {
        byte = buf[p++] ?? 0;
        strip = ((strip + 1) << 7) | (byte & 0x7f);
      }
      const end = buf.indexOf(0, p);
      if (end < 0) return undefined;
      if (strip > previous.length) return undefined;
      const bytes = Buffer.concat([previous.subarray(0, previous.length - strip), buf.subarray(p, end)]);
      name = bytes.toString('utf8');
      previous = bytes;
      p = end + 1;
    } else {
      const end = buf.indexOf(0, p);
      if (end < 0) return undefined;
      name = buf.toString('utf8', p, end);
      previous = buf.subarray(p, end);
      // 1件の長さが 8 の倍数になるよう、NUL で埋められている
      p = start + Math.ceil((end - start + 1) / 8) * 8;
    }
    paths.add(name);
  }
  return paths;
}
