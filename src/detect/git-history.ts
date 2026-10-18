// Git の履歴（過去のコミット）に残っている秘密情報を探す。いまのファイルから消えていても、履歴に残っていれば見つける。
//
// 方針：
// ・読み取りだけ。履歴の書き換え・自動修正はしない。使う git のコマンドは rev-list・cat-file・log・for-each-ref・branch（読み取り）だけ
// ・判定は、いまのファイルと同じ仕組み（secret-defs.ts の定義・秘密鍵の判定）を使う
// ・値は画面・ログ・結果に出さない。同じ値かどうかは、実行のたびに作って捨てる鍵の HMAC で比べる（指紋も結果には入れない）
// ・いまのファイルにまだある値は、いまのファイルの項目で知らせるので、ここでは数えない（同じ秘密情報を重ねて出さない）
// ・git が使えない・履歴が読めないときは、履歴のチェックだけを飛ばす（アプリ全体は失敗させない）
// ・大きな履歴のために、調べるファイルの版の数・容量・時間に上限を設ける
//
// 安全のため：
// ・git は PATH から絶対パスで探す。調べるフォルダの中の git は使わない（Windows は、作業フォルダの git.exe を先に実行してしまうことがあるため）
// ・GIT_DIR などの環境変数で、別のリポジトリに向けられないようにする。textconv・外部 diff を使う処理（log -p など）は使わない
// ・通信しない：部分的に取得したリポジトリ（partial clone）では、手元にないファイルの版を git が自動でリモートから取りに行くため、
//   GIT_NO_LAZY_FETCH で止め、さらに partial clone と分かったら履歴のチェックを飛ばす（この変数を知らない古い git のため）

import { spawnSync } from 'node:child_process';
import { createHmac, randomBytes } from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { delimiter, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { isEnvExampleName, isEnvFileName } from './env.js';
import { findPrivateKey, isKeyFileCandidate, type PrivateKeyKind } from './key-files.js';
import { findInEnv, findInText, textPlaceOf, type SecretNameHit } from './secret-names.js';

export interface HistoryLimits {
  /** 調べるファイルの版（blob）の数 */
  maxBlobs: number;
  /** 調べるファイルの版の合計の大きさ */
  maxBytes: number;
  /** 1つの版の大きさ（これより大きいものは調べない） */
  maxFileBytes: number;
  /** 全体の時間 */
  maxMillis: number;
  /** 知らせる件数 */
  maxFindings: number;
}

export const DEFAULT_HISTORY_LIMITS: HistoryLimits = { maxBlobs: 20_000, maxBytes: 64 * 1024 * 1024, maxFileBytes: 1024 * 1024, maxMillis: 20_000, maxFindings: 50 };

export interface HistoryFinding {
  kind: 'secret' | 'private-key';
  /** kind = secret のとき：定義の id（secret-defs.ts） */
  defId?: string;
  /** kind = private-key のとき */
  keyKind?: PrivateKeyKind;
  encrypted?: boolean;
  /** real-like：本物の形／uncertain：判断できない（ローカル開発用の形など） */
  value: 'real-like' | 'uncertain';
  /** 見つけたファイル（選んだフォルダからの相対パス。そのコミットの時点の名前） */
  file: string;
  /** そのファイルの版を最初に含んだコミット（短い SHA）と日付 */
  commit?: string;
  date?: string;
  /** yes：リモート（GitHub など）に push 済みの履歴にある／no：まだ push していない／no-remote：リモートがない／unknown：調べきれなかった */
  pushed: 'yes' | 'no' | 'no-remote' | 'unknown';
  /** 同じ値が見つかった場所の数（ファイルの版の数） */
  occurrences: number;
  /** 同じ値が見つかった、ほかのファイル（最大5件） */
  otherFiles: string[];
}

export interface GitHistoryResult {
  /** checked：調べた／not-repo：Git のリポジトリではない（または履歴を読めない）／no-git-command：git が見つからない／failed：調べられなかった */
  status: 'checked' | 'not-repo' | 'no-git-command' | 'failed';
  /** failed のときの理由（partial-clone：部分的に取得したリポジトリ。読むと通信が起きうるので読まない） */
  reason?: 'dubious-ownership' | 'timeout' | 'error' | 'partial-clone';
  /** 上限に達して、一部だけを調べた */
  truncated: boolean;
  stats: { commits: number; blobs: number; bytes: number };
  findings: HistoryFinding[];
}

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.next', '.expo', '.turbo', '.vercel', '.netlify', '.cache', '.parcel-cache',
  'dist', 'build', 'out', 'coverage', 'Pods', '.gradle', 'vendor', '.venv', 'venv', '__pycache__', 'target', '.idea', '.vscode',
]);

/** git の実行ファイルを、PATH から絶対パスで探す（調べるフォルダの中・相対パスの PATH は使わない） */
export function findGitExecutable(root: string, pathEnv: string | undefined = process.env.PATH ?? process.env.Path, platform: NodeJS.Platform = process.platform): string | undefined {
  const names = platform === 'win32' ? ['git.exe'] : ['git'];
  const rootAbs = resolve(root);
  for (const dir of (pathEnv ?? '').split(platform === 'win32' ? ';' : delimiter)) {
    const d = dir.trim().replace(/^"(.*)"$/, '$1');
    if (!d || !isAbsolute(d)) continue;
    const rel = relative(rootAbs, resolve(d));
    if (rel === '' || (!rel.startsWith('..') && !isAbsolute(rel))) continue; // 調べるフォルダの中
    for (const name of names) {
      const p = join(d, name);
      try {
        if (existsSync(p) && statSync(p).isFile()) return p;
      } catch {
        // 次へ
      }
    }
  }
  return undefined;
}

/** git に渡す環境変数（別のリポジトリに向ける変数を消し、入力を求めない・ロックを作らない） */
function gitEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (/^GIT_/i.test(k)) continue;
    env[k] = v;
  }
  // GIT_NO_LAZY_FETCH：手元にないオブジェクトをリモートから取りに行かない（partial clone で通信しないため）
  return { ...env, GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0', GIT_NO_REPLACE_OBJECTS: '1', GIT_NO_LAZY_FETCH: '1', GIT_CONFIG_NOSYSTEM: '1', LC_ALL: 'C', LANG: 'C' };
}

/**
 * 部分的に取得したリポジトリ（partial clone）か。.git/config を読むだけで判定する（git は動かさない）。
 * .git がファイル（worktree・submodule の「gitdir: …」）なら、その先を読む
 */
export function isPartialClone(gitRoot: string): boolean {
  try {
    let gitDir = join(gitRoot, '.git');
    if (statSync(gitDir).isFile()) {
      const m = /^gitdir:\s*(.+)$/m.exec(readFileSync(gitDir, 'utf8'));
      if (!m?.[1]) return false;
      gitDir = resolve(gitRoot, m[1].trim());
      // worktree の場合、設定は共通のフォルダ（commondir）にある
      const common = join(gitDir, 'commondir');
      if (existsSync(common)) gitDir = resolve(gitDir, readFileSync(common, 'utf8').trim());
    }
    const config = readFileSync(join(gitDir, 'config'), 'utf8');
    return /^\s*(promisor\s*=\s*true|partialclonefilter\s*=|partialclone\s*=)/im.test(config);
  } catch {
    return false;
  }
}

class GitFailure extends Error {
  constructor(readonly reason: 'not-repo' | 'dubious-ownership' | 'timeout' | 'error') {
    super(reason);
  }
}

/** 読み取りの git コマンドだけを許す */
const ALLOWED = new Set(['rev-list', 'cat-file', 'log', 'for-each-ref', 'branch', 'rev-parse']);

export function scanGitHistory(
  root: string,
  gitRoot: string,
  options: { git?: string | null; limits?: HistoryLimits; currentFingerprint?: (fp: string) => boolean; fingerprintKey: Buffer },
): GitHistoryResult {
  const limits = options.limits ?? DEFAULT_HISTORY_LIMITS;
  const empty = (status: GitHistoryResult['status'], reason?: GitHistoryResult['reason']): GitHistoryResult => ({
    status,
    ...(reason ? { reason } : {}),
    truncated: false,
    stats: { commits: 0, blobs: 0, bytes: 0 },
    findings: [],
  });
  const git = options.git === undefined ? findGitExecutable(root) : options.git;
  if (!git) return empty('no-git-command');
  if (isPartialClone(gitRoot)) return empty('failed', 'partial-clone');
  const deadline = Date.now() + limits.maxMillis;
  const env = gitEnv();

  const run = (args: string[], input?: Buffer, maxBuffer = 64 * 1024 * 1024): Buffer => {
    if (!ALLOWED.has(args[0] ?? '')) throw new GitFailure('error');
    const left = deadline - Date.now();
    if (left <= 0) throw new GitFailure('timeout');
    const r = spawnSync(git, ['-c', 'core.fsmonitor=false', '-c', 'core.quotepath=false', ...args], {
      cwd: gitRoot,
      env,
      input,
      maxBuffer,
      timeout: left,
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const stderr = r.stderr?.toString('utf8') ?? '';
    if (r.error) {
      const code = (r.error as NodeJS.ErrnoException).code;
      if (code === 'ETIMEDOUT') throw new GitFailure('timeout');
      if (code === 'ENOBUFS' && r.stdout) return r.stdout; // 上限まで読めた分だけ使う
      throw new GitFailure('error');
    }
    if (r.status !== 0) {
      if (/dubious ownership/i.test(stderr)) throw new GitFailure('dubious-ownership');
      if (/not a git repository/i.test(stderr)) throw new GitFailure('not-repo');
      throw new GitFailure('error');
    }
    return r.stdout ?? Buffer.alloc(0);
  };

  // 選んだフォルダが、リポジトリの中のどこか（モノレポの一部なら、その中だけを調べる）
  const prefixRel = relative(gitRoot, root).split(sep).join('/');
  const prefix = prefixRel === '' ? '' : `${prefixRel}/`;
  const toScanRel = (p: string) => (prefix && p.startsWith(prefix) ? p.slice(prefix.length) : p);

  let truncated = false;
  const stats = { commits: 0, blobs: 0, bytes: 0 };
  const hmac = (s: string) => createHmac('sha256', options.fingerprintKey).update(s).digest('hex');

  /** 指紋 → 見つけた場所 */
  const groups = new Map<string, { finding: Omit<HistoryFinding, 'occurrences' | 'otherFiles' | 'pushed' | 'commit' | 'date'>; blob: string; files: Set<string>; count: number }>();

  try {
    // 1. すべての参照（ブランチ・タグ・リモート・stash）から届くオブジェクトと、そのパス
    const listing = run(['rev-list', '--all', '--objects']).toString('utf8');
    const candidates: { sha: string; path: string }[] = [];
    for (const line of listing.split('\n')) {
      if (!line) continue;
      const space = line.indexOf(' ');
      if (space === -1) {
        stats.commits++;
        continue;
      }
      const sha = line.slice(0, space);
      const path = line.slice(space + 1);
      if (prefix && !path.startsWith(prefix)) continue;
      const parts = path.split('/');
      const name = parts[parts.length - 1] ?? '';
      if (parts.slice(0, -1).some((d) => SKIP_DIRS.has(d))) continue;
      if (!(isEnvFileName(name) || textPlaceOf(name) || isKeyFileCandidate(name))) continue;
      candidates.push({ sha, path });
    }

    // 2. 種類と大きさを確かめ、上限の範囲で選ぶ
    const selected: { sha: string; path: string }[] = [];
    if (candidates.length > 0) {
      const check = run(['cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)'], Buffer.from(candidates.map((c) => c.sha).join('\n') + '\n')).toString('utf8').split('\n');
      for (let i = 0; i < candidates.length; i++) {
        const [, type, sizeText] = (check[i] ?? '').split(' ');
        const size = Number(sizeText);
        if (type !== 'blob' || !Number.isFinite(size) || size > limits.maxFileBytes) continue;
        if (selected.length >= limits.maxBlobs || stats.bytes + size > limits.maxBytes) {
          truncated = true;
          break;
        }
        stats.bytes += size;
        selected.push(candidates[i] as { sha: string; path: string });
      }
    }
    stats.blobs = selected.length;

    // 3. 中身を読み、いまのファイルと同じ仕組みで調べる（値は指紋にしてすぐ捨てる）
    if (selected.length > 0) {
      const out = run(['cat-file', '--batch'], Buffer.from(selected.map((c) => c.sha).join('\n') + '\n'), stats.bytes + selected.length * 128 + 1024 * 1024);
      let pos = 0;
      for (const c of selected) {
        const nl = out.indexOf(10, pos);
        if (nl === -1) {
          truncated = true;
          break;
        }
        const header = out.toString('latin1', pos, nl).split(' ');
        if (header[1] === 'missing') {
          // 手元にない版（取りに行かない）
          pos = nl + 1;
          continue;
        }
        const size = Number(header[2]);
        if (!Number.isFinite(size)) {
          truncated = true;
          break;
        }
        const body = out.subarray(nl + 1, nl + 1 + size);
        pos = nl + 1 + size + 1;
        if (body.subarray(0, 8192).includes(0)) continue; // バイナリ
        const text = body.toString('utf8').replace(/^﻿/, '');
        const file = toScanRel(c.path);
        const name = file.split('/').pop() ?? '';
        const add = (fp: string, finding: Omit<HistoryFinding, 'occurrences' | 'otherFiles' | 'pushed' | 'commit' | 'date'>) => {
          const g = groups.get(fp);
          if (g) {
            g.count++;
            g.files.add(file);
            if (finding.value === 'real-like') g.finding.value = 'real-like';
          } else {
            groups.set(fp, { finding, blob: c.sha, files: new Set([file]), count: 1 });
          }
        };
        const onValue = (hit: SecretNameHit, value: string) => {
          const kind = hit.value?.kind;
          if (kind !== 'real-like' && kind !== 'uncertain') return;
          add(hmac(`secret\0${hit.defId}\0${value.trim()}`), { kind: 'secret', defId: hit.defId, value: kind, file });
        };
        if (isEnvFileName(name)) findInEnv(text, file, isEnvExampleName(name), onValue);
        const place = textPlaceOf(name);
        if (place) findInText(text, file, place, onValue);
        if (place || isKeyFileCandidate(name)) {
          let keyFp: string | undefined;
          const key = findPrivateKey(text, (b) => (keyFp = hmac(`key\0${b}`)));
          // ダミー以外は数える（本物か判断できない鍵は、安全とは扱わず 🟠 にする）
          if (key && key.value !== 'test-like' && keyFp) add(keyFp, { kind: 'private-key', keyKind: key.kind, encrypted: key.encrypted, value: key.value, file });
        }
        if (Date.now() > deadline) {
          truncated = true;
          break;
        }
      }
    }
  } catch (e) {
    if (e instanceof GitFailure) {
      if (e.reason === 'not-repo') return empty('not-repo');
      if (e.reason === 'timeout' && groups.size === 0) return { ...empty('failed', 'timeout'), stats };
      if (e.reason !== 'timeout') return empty('failed', e.reason);
      truncated = true;
    } else {
      return empty('failed', 'error');
    }
  }

  // 4. いまのファイルにまだある値は除く（いまのファイルの項目で知らせる）
  const remaining = [...groups.entries()].filter(([fp]) => !(options.currentFingerprint?.(fp) ?? false));
  if (remaining.length > limits.maxFindings) truncated = true;

  // 5. どのコミットで入ったか・push 済みか
  let remotes = false;
  try {
    remotes = run(['for-each-ref', '--format=%(refname)', 'refs/remotes']).toString('utf8').trim() !== '';
  } catch {
    remotes = false;
  }
  const findings: HistoryFinding[] = [];
  for (const [, g] of remaining.slice(0, limits.maxFindings)) {
    let commit: string | undefined;
    let date: string | undefined;
    let pushed: HistoryFinding['pushed'] = 'unknown';
    try {
      const lines = run(['log', '--all', '--no-ext-diff', '--no-textconv', '--format=%H %cI', `--find-object=${g.blob}`]).toString('utf8').trim().split('\n').filter(Boolean);
      const oldest = lines[lines.length - 1]?.split(' ');
      if (oldest?.[0]) {
        commit = oldest[0].slice(0, 7);
        date = oldest[1]?.slice(0, 10);
        if (!remotes) pushed = 'no-remote';
        else pushed = run(['branch', '-r', '--contains', oldest[0]]).toString('utf8').trim() !== '' ? 'yes' : 'no';
      }
    } catch {
      truncated = true;
    }
    const files = [...g.files];
    findings.push({ ...g.finding, file: files[0] ?? g.finding.file, ...(commit ? { commit } : {}), ...(date ? { date } : {}), pushed, occurrences: g.count, otherFiles: files.slice(1, 6) });
  }
  return { status: 'checked', truncated, stats, findings };
}

/** 実行のたびに作る指紋の鍵（保存しない） */
export function newFingerprintKey(): Buffer {
  return randomBytes(32);
}

/** いまのファイルの値の指紋（履歴と同じ作り方） */
export function secretFingerprint(key: Buffer, defId: string, value: string): string {
  return createHmac('sha256', key).update(`secret\0${defId}\0${value.trim()}`).digest('hex');
}

export function keyFingerprint(key: Buffer, body: string): string {
  return createHmac('sha256', key).update(`key\0${body}`).digest('hex');
}
