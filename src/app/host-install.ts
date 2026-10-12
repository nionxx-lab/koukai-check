// 専用ウィンドウの部品（koukai-check-window.exe と、Microsoft 公式の WebView2Loader.dll）を、
// exe の中から取り出して、利用者のフォルダ（%LOCALAPPDATA%\koukai-check\window\<内容のハッシュ>\）に置く。
//
// ・exe の中身（SEA の assets）と同じ内容かどうかを SHA256 で確かめ、違えば書き直す。起動の直前にも確かめる。
// ・一時ファイルに書いてから名前を変えるので、書きかけのファイルを起動することはない。
// ・内容ごとに別のフォルダにするので、古い版が使用中でも新しい版を置ける。古い版のフォルダは消せたら消す。

import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export const HOST_EXE_NAME = 'koukai-check-window.exe';
export const LOADER_DLL_NAME = 'WebView2Loader.dll';
/** SEA の assets に入れるときの名前 */
export const HOST_ASSET_KEYS = [`windows-host/${HOST_EXE_NAME}`, `windows-host/${LOADER_DLL_NAME}`] as const;

export interface HostFile {
  name: string;
  data: Uint8Array;
}

function sha256(data: Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

function sameContent(path: string, expected: string): boolean {
  try {
    return sha256(readFileSync(path)) === expected;
  } catch {
    return false;
  }
}

export function defaultInstallBase(env: NodeJS.ProcessEnv = process.env): string {
  const local = env.LOCALAPPDATA && /^[A-Za-z]:\\/.test(env.LOCALAPPDATA) ? env.LOCALAPPDATA : join(homedir(), 'AppData', 'Local');
  return join(local, 'koukai-check', 'window');
}

/** 部品を置き、専用ウィンドウの exe のパスを返す */
export function installHostFiles(files: HostFile[], baseDir: string): string {
  if (!files.some((f) => f.name === HOST_EXE_NAME)) throw new Error('専用ウィンドウの部品がありません');
  for (const f of files) {
    if (!/^[A-Za-z0-9._-]+$/.test(f.name)) throw new Error(`部品の名前が不正です: ${f.name}`);
  }
  const hashes = new Map(files.map((f) => [f.name, sha256(f.data)]));
  const version = createHash('sha256')
    .update([...hashes.entries()].map(([n, h]) => `${n}:${h}`).join('\n'))
    .digest('hex')
    .slice(0, 16);
  const dir = join(baseDir, version);
  mkdirSync(dir, { recursive: true });

  for (const f of files) {
    const target = join(dir, f.name);
    const expected = hashes.get(f.name) ?? '';
    if (sameContent(target, expected)) continue;
    const tmp = join(dir, `.${f.name}.${randomBytes(6).toString('hex')}.tmp`);
    writeFileSync(tmp, f.data, { mode: 0o755 });
    try {
      renameSync(tmp, target);
    } catch (error) {
      rmSync(tmp, { force: true });
      throw error;
    }
  }
  // 起動の直前に、もう一度中身を確かめる
  for (const f of files) {
    if (!sameContent(join(dir, f.name), hashes.get(f.name) ?? '')) throw new Error('専用ウィンドウの部品を正しく書き込めませんでした');
  }

  // 古い版の部品は、使われていなければ消す（使用中で消せなくても気にしない）
  try {
    for (const entry of readdirSync(baseDir)) {
      if (entry !== version && /^[0-9a-f]{16}$/.test(entry)) rmSync(join(baseDir, entry), { recursive: true, force: true });
    }
  } catch {
    // 何もしない
  }
  return join(dir, HOST_EXE_NAME);
}

/** exe（SEA）の中に入っている部品を読む。入っていなければ undefined */
export function readSeaHostFiles(getAsset: (key: string) => ArrayBuffer): HostFile[] | undefined {
  try {
    return HOST_ASSET_KEYS.map((key) => ({ name: key.slice(key.indexOf('/') + 1), data: new Uint8Array(getAsset(key)) }));
  } catch {
    return undefined;
  }
}
