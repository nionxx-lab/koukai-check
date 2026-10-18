// 選ばれたフォルダから、使われている技術をローカルで判定する。
//
// ・読み取りのみ（書き込み・実行・通信はしない）
// ・node_modules や .git などの大きなフォルダには入らない。深さ・件数・ファイルサイズに上限を設ける
// ・シンボリックリンクはたどらない（選んだフォルダの外を読まないため）
// ・選んだフォルダの直下の package.json・.env 系・主要な設定ファイルは、上限に関係なく最初に必ず確認する
//   （フォルダが大きくても、アプリのルートの判定を取りこぼさないため）
// ・ファイル先頭の BOM（Windows のメモ帳や PowerShell 5.1 が付けることがある）は取り除いてから読む
// ・判定の根拠として外へ出すのは、相対パス・パッケージ名・環境変数の「名前」だけ

import { closeSync, existsSync, lstatSync, openSync, readdirSync, readFileSync, readSync, realpathSync, statSync } from 'node:fs';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';
import { isEnvExampleName, isEnvFileName, parseEnv, type SecretValueKind } from './env.js';
import { analyzeDatabaseRules, analyzeServiceRules, DEFAULT_RULES_FILES, firebaseJsonPaths, type RuleFinding, type RulesKind } from './firebase-rules.js';
import { dbBackupKind, envHasValues, findPrivateKeys, isKeyFileCandidate, isOAuthClientSecretJson, PUBLIC_DIR_NAMES, type PrivateKeyKind } from './key-files.js';
import { isIgnored, parseGitignore, type GitignoreRules } from './gitignore.js';
import { readGitIndex } from './git-index.js';
import { keyFingerprint, newFingerprintKey, scanGitHistory, secretFingerprint, type GitHistoryResult, type HistoryLimits } from './git-history.js';
import { isDefinedSecretName } from './secret-defs.js';
import { findInEnv, findInText, hasLocalSupabaseUrl, textPlaceOf, type SecretNameHit } from './secret-names.js';

export type { SecretNameHit };

export type TechId = 'supabase' | 'firebase' | 'expo' | 'react-native' | 'nextjs' | 'external-api' | 'env' | 'credentials';

export interface DetectedTech {
  id: TechId;
  /** 判定の根拠（相対パス・パッケージ名・変数名）。値は含めない */
  evidence: string[];
}

export interface EnvFileInfo {
  path: string;
  isExample: boolean;
  keyCount: number;
  /** 公開用の変数のうち、秘密情報らしいもの（名前と理由だけ） */
  publicSecretKeys: { name: string; reason: 'name' | SecretValueKind }[];
  /** Git での扱い */
  git: 'ignored' | 'not-ignored' | 'no-git';
}

export interface ScanResult {
  root: string;
  rootName: string;
  techs: DetectedTech[];
  supabaseRefs: string[];
  envFiles: EnvFileInfo[];
  externalApis: { name: string; via: string }[];
  /** 秘密情報の候補の変数名が見つかった場所（値は含めない） */
  secretNames: SecretNameLocation[];
  /** Firebase のセキュリティルール（このPCの中のファイル。デプロイ済みのルールとは限らない） */
  firebaseRules: { files: { file: string; kind: RulesKind; parsed: boolean }[]; findings: (RuleFinding & { file: string; kind: RulesKind })[] };
  /** 中身から秘密鍵・サービスアカウント鍵と確認できたファイル（鍵そのものは含めない） */
  privateKeys: PrivateKeyLocation[];
  /** 公開フォルダ（public/・static/ など）の中の、公開してはいけないファイル（秘密鍵・秘密情報の値は別に数える） */
  publicExposures: PublicExposure[];
  /** Git の履歴（過去のコミット）に残っている秘密情報（値は含めない） */
  gitHistory: GitHistoryResult;
  /** 選んだフォルダの直下の package.json の状態 */
  rootPackageJson: 'found' | 'missing' | 'invalid';
  /**
   * entries：調べた数／truncated：件数の上限に達して、調べていないフォルダがある／
   * depthLimited：深さの上限より深いフォルダは調べていない（ふつうのアプリでもよくある）／unreadable：読み取れなかった数
   */
  stats: { entries: number; truncated: boolean; depthLimited: boolean; unreadable: number };
}

/**
 * Git での状態
 *   tracked：Git が管理している（コミット済み・追加済み。.gitignore に書かれていても公開される）
 *   untracked：まだ追加されていないが、.gitignore で除外されていない（git add . で追加される）
 *   ignored：管理されておらず、.gitignore で除外されている
 *   not-ignored：.gitignore で除外されていない（Git の index を読めなかったため、管理されているかは不明）
 *   no-git：Git で管理されていないフォルダ
 */
export type GitState = 'tracked' | 'untracked' | 'ignored' | 'not-ignored' | 'no-git';

export interface SecretNameLocation extends SecretNameHit {
  git: GitState;
  /** Web からそのまま配信される公開フォルダ（public/・static/ など）の中なら、そのフォルダ */
  publicDir?: string;
  /** テスト結果・ビルド結果などの、自動で作られるフォルダの中か（判定は Git の状態で行う。目安として表示するだけ） */
  generated: boolean;
}

export interface PrivateKeyLocation {
  file: string;
  line: number;
  kind: PrivateKeyKind;
  /** real-like：本物の鍵の構造／test-like：はっきりしたダミー（数えない）／uncertain：本物か判断できない（確認をおすすめ） */
  value: 'real-like' | 'test-like' | 'uncertain';
  /** パスフレーズで暗号化されている */
  encrypted: boolean;
  /** 鍵を組み立てる式に、復元できない部分（変数・呼び出し）がある */
  unresolved?: boolean;
  git: GitState;
  publicDir?: string;
}

/**
 * env：値の入った .env／db-backup：データベースのファイル・バックアップ／db-sql：データ入りの SQL（見本の可能性あり）／
 * credential-json：OAuth クライアントの秘密（client_secret）入りの JSON
 */
export interface PublicExposure {
  file: string;
  kind: 'env' | 'db-backup' | 'db-sql' | 'credential-json';
  publicDir: string;
  git: GitState;
}

/** 自動で作られるファイルが入ることが多いフォルダ */
const GENERATED_DIRS = new Set(['test-results', 'playwright-report', 'coverage', '.nyc_output', 'reports', 'tmp', 'temp', 'logs', 'artifacts', 'snapshots', '__snapshots__']);

export interface ScanLimits {
  maxDepth: number;
  maxEntries: number;
  maxFileBytes: number;
}

export const DEFAULT_LIMITS: ScanLimits = { maxDepth: 4, maxEntries: 20_000, maxFileBytes: 1024 * 1024 };

/** 秘密情報の候補の変数名を探すために読む、ソース・設定ファイルの合計の上限 */
const MAX_TEXT_SEARCH_BYTES = 64 * 1024 * 1024;

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.next', '.expo', '.turbo', '.vercel', '.netlify', '.cache', '.parcel-cache',
  'dist', 'build', 'out', 'coverage', 'Pods', '.gradle', 'vendor', '.venv', 'venv', '__pycache__', 'target', '.idea', '.vscode',
]);

// ───────────── 判定ルール（データ） ─────────────

const PACKAGE_RULES: { tech: TechId; match: (name: string) => boolean }[] = [
  { tech: 'supabase', match: (n) => n === '@supabase/supabase-js' || n === '@supabase/ssr' || n.startsWith('@supabase/auth-helpers') || n === 'supabase' },
  { tech: 'firebase', match: (n) => n === 'firebase' || n === 'firebase-admin' || n.startsWith('@react-native-firebase/') || n === 'react-native-firebase' },
  { tech: 'expo', match: (n) => n === 'expo' },
  { tech: 'react-native', match: (n) => n === 'react-native' },
  { tech: 'nextjs', match: (n) => n === 'next' },
];

/** 外部APIのSDK（パッケージ名 → 表示名） */
export const EXTERNAL_API_PACKAGES: Record<string, string> = {
  openai: 'OpenAI',
  '@anthropic-ai/sdk': 'Anthropic（Claude）',
  '@google/generative-ai': 'Google Gemini',
  '@google/genai': 'Google Gemini',
  '@mistralai/mistralai': 'Mistral',
  'groq-sdk': 'Groq',
  'cohere-ai': 'Cohere',
  replicate: 'Replicate',
  '@elevenlabs/elevenlabs-js': 'ElevenLabs',
  elevenlabs: 'ElevenLabs',
  stripe: 'Stripe',
  '@stripe/stripe-js': 'Stripe',
  '@stripe/stripe-react-native': 'Stripe',
  resend: 'Resend',
  '@sendgrid/mail': 'SendGrid',
  twilio: 'Twilio',
  algoliasearch: 'Algolia',
  ai: 'Vercel AI SDK',
};

/** 外部APIのキーらしい環境変数名 → 表示名 */
const EXTERNAL_API_ENV: [RegExp, string][] = [
  [/OPENAI/i, 'OpenAI'],
  [/ANTHROPIC|CLAUDE/i, 'Anthropic（Claude）'],
  [/GEMINI|GOOGLE_(GENAI|AI)/i, 'Google Gemini'],
  [/STRIPE/i, 'Stripe'],
  [/ELEVENLABS|ELEVEN_LABS/i, 'ElevenLabs'],
  [/REPLICATE/i, 'Replicate'],
  [/RESEND/i, 'Resend'],
  [/SENDGRID/i, 'SendGrid'],
  [/TWILIO/i, 'Twilio'],
  [/GROQ/i, 'Groq'],
  [/MISTRAL/i, 'Mistral'],
];

const FILE_RULES: { tech: TechId; match: (rel: string, name: string) => boolean }[] = [
  { tech: 'supabase', match: (rel) => /(^|\/)supabase\/config\.toml$/.test(rel) },
  { tech: 'firebase', match: (_r, n) => ['firebase.json', '.firebaserc', 'google-services.json', 'GoogleService-Info.plist', 'firestore.rules', 'storage.rules', 'database.rules.json'].includes(n) },
  { tech: 'expo', match: (_r, n) => n === 'eas.json' || /^app\.config\.(js|ts|mjs|cjs|json)$/.test(n) },
  { tech: 'nextjs', match: (_r, n) => /^next\.config\.(js|mjs|cjs|ts)$/.test(n) },
];

/** 選んだフォルダの直下で、上限に関係なく最初に必ず確認するファイル（.env 系は別に判定する） */
export const ROOT_PRIORITY_FILES: ReadonlySet<string> = new Set([
  'package.json',
  'app.json',
  'app.config.js', 'app.config.ts', 'app.config.mjs', 'app.config.cjs', 'app.config.json',
  'eas.json',
  'next.config.js', 'next.config.mjs', 'next.config.cjs', 'next.config.ts',
  'firebase.json', '.firebaserc', 'google-services.json', 'GoogleService-Info.plist', 'firestore.rules', 'storage.rules', 'database.rules.json',
]);

/** 公開フォルダの中で、秘密情報の値を探すために読むテキストのファイル（設定ファイル・ソースコード以外） */
const PUBLIC_TEXT_EXT = /\.(txt|html?|map|md|csv|log)$/i;

// ───────────── 走査 ─────────────

function safeRead(path: string, maxBytes: number): string | undefined {
  try {
    const st = statSync(path);
    if (!st.isFile() || st.size > maxBytes) return undefined;
    // 先頭の BOM を取り除く（残っていると JSON.parse が失敗し、.env の最初の変数名にも混ざる）
    return readFileSync(path, 'utf8').replace(/^\uFEFF/, '');
  } catch {
    return undefined;
  }
}

/** ファイルの先頭だけを読む（大きなデータベースのファイルでも、種類を見分けるため） */
function readHead(path: string, bytes: number): Buffer {
  const buf = Buffer.alloc(bytes);
  let fd: number | undefined;
  try {
    fd = openSync(path, 'r');
    const n = readSync(fd, buf, 0, bytes, 0);
    return buf.subarray(0, n);
  } catch {
    return Buffer.alloc(0);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function toRel(root: string, path: string): string {
  return relative(root, path).split(sep).join('/');
}

/** 選ばれたフォルダを含む Git リポジトリのルート（読み取りのみ） */
function findGitRoot(start: string): string | undefined {
  let dir = start;
  for (let i = 0; i < 40; i++) {
    if (existsSync(join(dir, '.git'))) return dir;
    const parent = dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
  return undefined;
}

export class ScanError extends Error {
  constructor(readonly kind: 'not-found' | 'not-directory' | 'unreadable', message: string) {
    super(message);
  }
}

export interface ScanOptions {
  now?: Date;
  /** Git の履歴のチェック。false で行わない。git：使う git（null で「見つからない」とみなす。テスト用） */
  history?: false | { git?: string | null; limits?: HistoryLimits };
}

export function scanProject(inputPath: string, limits: ScanLimits = DEFAULT_LIMITS, options: ScanOptions = {}): ScanResult {
  const now = options.now ?? new Date();
  // 同じ秘密情報かどうかを、値を残さずに比べるための指紋（鍵はこの実行の中だけで使い、指紋も結果には入れない）
  const fingerprintKey = newFingerprintKey();
  const currentFingerprints = new Set<string>();
  const remember = (hit: SecretNameHit, value: string) => {
    if (hit.value?.kind === 'real-like' || hit.value?.kind === 'uncertain') currentFingerprints.add(secretFingerprint(fingerprintKey, hit.defId, value));
  };
  const requested = resolve(inputPath.trim());
  let root: string;
  try {
    root = realpathSync(requested);
  } catch {
    throw new ScanError('not-found', 'フォルダが見つかりません');
  }
  let st;
  try {
    st = statSync(root);
  } catch {
    throw new ScanError('unreadable', 'フォルダを読み取れません');
  }
  if (!st.isDirectory()) throw new ScanError('not-directory', 'フォルダではありません');

  const evidence = new Map<TechId, Set<string>>();
  const add = (tech: TechId, ev: string) => {
    if (!evidence.has(tech)) evidence.set(tech, new Set());
    evidence.get(tech)?.add(ev);
  };
  const refs = new Set<string>();
  const externalApis = new Map<string, string>();
  const envPaths: string[] = [];
  const stats = { entries: 0, truncated: false, depthLimited: false, unreadable: 0 };
  let rootPackageJson: ScanResult['rootPackageJson'] = 'missing';
  const secretHits: SecretNameHit[] = [];
  let searchedBytes = 0;
  const rulesFiles = new Map<string, RulesKind>(); // 絶対パス → 種類
  const hostingDirs = new Set<string>(); // 直下の firebase.json に書かれた Hosting の公開フォルダ
  const keyHits: Omit<PrivateKeyLocation, 'git' | 'publicDir'>[] = [];
  const exposures: Omit<PublicExposure, 'git'>[] = [];

  /** Web からそのまま配信される公開フォルダの中なら、そのフォルダ（相対パス） */
  const publicDirOf = (rel: string): string | undefined => {
    const parts = rel.split('/');
    for (let i = 0; i < parts.length - 1; i++) {
      const dir = parts.slice(0, i + 1).join('/');
      if (PUBLIC_DIR_NAMES.has(parts[i] ?? '') || hostingDirs.has(dir)) return dir;
    }
    return undefined;
  };
  /** 選んだフォルダの中のパスか（firebase.json に書かれた場所が、外を指していないか） */
  const insideRoot = (abs: string) => {
    const r = relative(root, abs);
    return r !== '' && !r.startsWith('..') && !/^[a-zA-Z]:/.test(r) && !r.startsWith(sep);
  };

  /** 公開フォルダの中のファイル：データベースのファイル・バックアップ（先頭の決まった形だけで判定） */
  const inspectPublicFile = (path: string, name: string, rel: string, pub: string) => {
    const head = readHead(path, 16);
    const sqlText = /\.sql$/i.test(name) ? readHead(path, 64 * 1024).toString('utf8') : undefined;
    const db = dbBackupKind(head, name, sqlText);
    if (db) exposures.push({ file: rel, kind: db, publicDir: pub });
  };

  /** 1つのファイルを調べる（ルートの優先確認と、全体の走査の両方で使う） */
  const inspectFile = (path: string, name: string, rel: string) => {
    for (const rule of FILE_RULES) if (rule.match(rel, name)) add(rule.tech, rel);
    const ruleKind = DEFAULT_RULES_FILES[name];
    if (ruleKind) rulesFiles.set(path, ruleKind);
    if (name === 'firebase.json') {
      const text = safeRead(path, limits.maxFileBytes);
      if (text !== undefined) {
        const found = firebaseJsonPaths(text);
        for (const r of found.rules) {
          const abs = resolve(dirname(path), r.path);
          if (insideRoot(abs)) rulesFiles.set(abs, r.kind);
        }
        // 公開フォルダ（Hosting）は、直下の firebase.json に書かれたものだけを使う（ほかのファイルより先に読むため）
        if (rel === 'firebase.json') {
          for (const dir of found.hostingPublic) {
            const abs = resolve(root, dir);
            if (insideRoot(abs)) hostingDirs.add(toRel(root, abs));
          }
        }
      }
    }
    const pub = publicDirOf(rel);
    if (pub && !isEnvFileName(name)) inspectPublicFile(path, name, rel, pub);

    if (name === 'package.json') {
      const text = safeRead(path, limits.maxFileBytes);
      let pkg: Record<string, unknown> | undefined;
      try {
        const parsed: unknown = text === undefined ? undefined : JSON.parse(text);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) pkg = parsed as Record<string, unknown>;
      } catch {
        pkg = undefined;
      }
      if (rel === 'package.json') rootPackageJson = pkg ? 'found' : 'invalid';
      if (!pkg) {
        stats.unreadable++;
        return;
      }
      const deps = { ...(pkg.dependencies as object), ...(pkg.devDependencies as object) } as Record<string, unknown>;
      for (const dep of Object.keys(deps)) {
        for (const rule of PACKAGE_RULES) if (rule.match(dep)) add(rule.tech, `${rel}: ${dep}`);
        const api = EXTERNAL_API_PACKAGES[dep];
        if (api) {
          add('external-api', `${rel}: ${dep}`);
          if (!externalApis.has(api)) externalApis.set(api, dep);
        }
      }
    } else if (name === 'app.json') {
      const text = safeRead(path, limits.maxFileBytes);
      if (text && /"expo"\s*:/.test(text)) add('expo', rel);
      if (text) for (const m of text.matchAll(/https:\/\/([a-z]{20})\.supabase\.co/g)) if (m[1]) refs.add(m[1]);
    } else if (isEnvFileName(name)) {
      envPaths.push(path);
      return;
    }
    // 秘密情報の候補の変数名を、設定ファイル・ソースコードの中から探す（値は外へ出さない）
    const place = textPlaceOf(name) ?? (pub && PUBLIC_TEXT_EXT.test(name) ? 'other' : undefined);
    const keyCandidate = isKeyFileCandidate(name);
    if ((place || keyCandidate) && searchedBytes < MAX_TEXT_SEARCH_BYTES) {
      const text = safeRead(path, limits.maxFileBytes);
      if (text === undefined) return;
      searchedBytes += text.length;
      if (place) secretHits.push(...findInText(text, rel, place, remember));
      // 秘密鍵・サービスアカウント鍵（中身で判定する。ファイル名・拡張子では判定しない）
      // 同じファイルに複数の鍵があれば、それぞれを結果にする
      for (const key of findPrivateKeys(text, (body) => currentFingerprints.add(keyFingerprint(fingerprintKey, body)))) keyHits.push({ file: rel, ...key });
      if (pub && name.toLowerCase().endsWith('.json') && isOAuthClientSecretJson(text)) exposures.push({ file: rel, kind: 'credential-json', publicDir: pub });
    }
  };

  // 1. 選んだフォルダの直下を、上限に関係なく最初に確認する
  const done = new Set<string>();
  let rootNames: string[] = [];
  try {
    rootNames = readdirSync(root).sort();
  } catch {
    stats.unreadable++;
  }
  const priority = rootNames.filter((n) => ROOT_PRIORITY_FILES.has(n) || isEnvFileName(n)).map((n) => ({ path: join(root, n), name: n }));
  priority.push({ path: join(root, 'supabase', 'config.toml'), name: 'config.toml' });
  for (const { path, name } of priority) {
    try {
      // シンボリックリンクは、途中のフォルダも含めてたどらない
      if (path.endsWith(join('supabase', 'config.toml')) && lstatSync(join(root, 'supabase')).isSymbolicLink()) continue;
      const ls = lstatSync(path);
      if (ls.isSymbolicLink() || !ls.isFile()) continue;
    } catch {
      continue;
    }
    done.add(path);
    inspectFile(path, name, toRel(root, path));
  }

  // 2. フォルダ全体を、深さ・件数の上限の範囲で調べる
  const queue: { dir: string; depth: number }[] = [{ dir: root, depth: 0 }];
  while (queue.length > 0) {
    const { dir, depth } = queue.shift() as { dir: string; depth: number };
    let names: string[];
    if (dir === root) {
      names = rootNames;
    } else {
      try {
        names = readdirSync(dir).sort();
      } catch {
        stats.unreadable++;
        continue;
      }
    }
    for (const name of names) {
      const path = join(dir, name);
      if (done.has(path)) continue; // 1. で確認済み
      if (stats.entries >= limits.maxEntries) {
        stats.truncated = true;
        break;
      }
      stats.entries++;
      let ls;
      try {
        ls = lstatSync(path);
      } catch {
        stats.unreadable++;
        continue;
      }
      if (ls.isSymbolicLink()) continue;
      const rel = toRel(root, path);

      if (ls.isDirectory()) {
        if (SKIP_DIRS.has(name)) continue;
        if (depth + 1 <= limits.maxDepth) queue.push({ dir: path, depth: depth + 1 });
        else stats.depthLimited = true;
        continue;
      }
      if (!ls.isFile()) continue;
      inspectFile(path, name, rel);
    }
  }

  // .env 系ファイル
  const gitRoot = findGitRoot(root);
  const gitignoreCache = new Map<string, GitignoreRules | null>();
  const rulesFor = (envPath: string) => {
    if (!gitRoot) return [];
    const list: { base: string; rules: GitignoreRules }[] = [];
    const dirs: string[] = [];
    for (let d = dirname(envPath); ; d = dirname(d)) {
      dirs.unshift(d);
      if (d === gitRoot || dirname(d) === d) break;
    }
    for (const d of dirs) {
      if (!gitignoreCache.has(d)) {
        const text = safeRead(join(d, '.gitignore'), limits.maxFileBytes);
        gitignoreCache.set(d, text === undefined ? null : parseGitignore(text));
      }
      const rules = gitignoreCache.get(d);
      if (rules) list.push({ base: toRel(gitRoot, d) === '' ? '' : toRel(gitRoot, d), rules });
    }
    return list;
  };

  // Git が管理しているファイルの一覧（.git/index）。読めなければ .gitignore だけで判定する
  const tracked = gitRoot ? readGitIndex(gitRoot) : undefined;
  const gitStateOf = (rel: string): GitState => {
    if (!gitRoot) return 'no-git';
    const abs = join(root, ...rel.split('/'));
    const fromGitRoot = toRel(gitRoot, abs);
    if (tracked?.has(fromGitRoot)) return 'tracked';
    const ignored = isIgnored(fromGitRoot, rulesFor(abs));
    if (ignored) return 'ignored';
    return tracked ? 'untracked' : 'not-ignored';
  };

  const envFiles: EnvFileInfo[] = [];
  let envHasLocalSupabaseUrl = false;
  for (const path of envPaths) {
    const name = basename(path);
    const isExample = isEnvExampleName(name);
    const text = safeRead(path, limits.maxFileBytes);
    if (text === undefined) {
      stats.unreadable++;
      continue;
    }
    const parsed = parseEnv(text);
    add('env', toRel(root, path));
    // 公開フォルダの中の .env は、Git の対象外でも公開されるビルドに含まれうる（見本の .env は、秘密の値があるときだけ値として数える）
    const envPub = publicDirOf(toRel(root, path));
    if (envPub && !isExample && envHasValues(text)) exposures.push({ file: toRel(root, path), kind: 'env', publicDir: envPub });
    secretHits.push(...findInEnv(text, toRel(root, path), isExample, remember));
    if (!isExample && hasLocalSupabaseUrl(text)) envHasLocalSupabaseUrl = true;
    const publicSecretKeys: EnvFileInfo['publicSecretKeys'] = [];
    for (const key of parsed.keys) {
      if (/SUPABASE/i.test(key.name)) add('supabase', `${toRel(root, path)}: ${key.name}`);
      if (/FIREBASE/i.test(key.name)) add('firebase', `${toRel(root, path)}: ${key.name}`);
      for (const [re, api] of EXTERNAL_API_ENV) {
        // CLAUDE_CODE_OAUTH_TOKEN などは、専用の案内で扱う（一般的な API キーとしては数えない）
        if (isDefinedSecretName(key.name)) break;
        if (re.test(key.name)) {
          add('external-api', `${toRel(root, path)}: ${key.name}`);
          if (!externalApis.has(api)) externalApis.set(api, key.name);
        }
      }
      if (!isExample && key.isPublic && (key.secretLikeValue || key.secretLikeName)) {
        publicSecretKeys.push({ name: key.name, reason: key.secretLikeValue ?? 'name' });
      }
    }
    if (!isExample) for (const r of parsed.supabaseRefs) refs.add(r);
    envFiles.push({
      path: toRel(root, path),
      isExample,
      keyCount: parsed.keys.length,
      publicSecretKeys,
      // コミット済みなら、.gitignore に書かれていても公開される
      git: (() => {
        const state = gitStateOf(toRel(root, path));
        return state === 'no-git' ? 'no-git' : state === 'ignored' ? 'ignored' : 'not-ignored';
      })(),
    });
  }

  // ローカル開発用の Supabase の鍵（iss: supabase-demo）は、それだけでは安全としない。
  // 同じファイルにローカルの URL がある、または supabase/config.toml とローカルの URL（.env）の両方がある場合だけ、ローカル用とする。
  // どちらでもなければ「要確認」のまま（安全とは扱わない）
  const hasConfigToml = evidence.get('supabase')?.has('supabase/config.toml') ?? false;
  for (const h of secretHits) {
    if (h.value?.reason !== 'local-unconfirmed') continue;
    if (h.localHint || (hasConfigToml && envHasLocalSupabaseUrl)) h.value = { kind: 'test-like', reason: 'local-dev' };
  }

  // 秘密情報：Git での状態を付ける
  const secretNames: SecretNameLocation[] = secretHits.slice(0, 200).map((h) => {
    const loc: SecretNameLocation = { ...h, git: gitStateOf(h.file), generated: h.file.split('/').slice(0, -1).some((d) => GENERATED_DIRS.has(d)) };
    const pub = publicDirOf(h.file);
    if (pub) loc.publicDir = pub;
    return loc;
  });
  // 秘密情報は「認証情報」としてまとめる（値の形で見つけたものは変数名がないので、場所だけ）
  for (const h of secretNames) add('credentials', h.as ? `${h.file}: ${h.as}` : `${h.file}:${h.line}`);

  // 秘密鍵・公開フォルダ：Git での状態を付ける
  const privateKeys: PrivateKeyLocation[] = keyHits.slice(0, 200).map((k) => {
    const loc: PrivateKeyLocation = { ...k, git: gitStateOf(k.file) };
    const pub = publicDirOf(k.file);
    if (pub) loc.publicDir = pub;
    return loc;
  });
  for (const k of privateKeys) if (k.value !== 'test-like') add('credentials', k.file);
  const publicExposures: PublicExposure[] = exposures.slice(0, 200).map((x) => ({ ...x, git: gitStateOf(x.file) }));
  for (const x of publicExposures) add('credentials', x.file);

  // Git の履歴（過去のコミット）。いまのファイルにまだある値は除く
  const gitHistory: GitHistoryResult =
    options.history === false || !gitRoot
      ? { status: 'not-repo', truncated: false, stats: { commits: 0, blobs: 0, bytes: 0 }, findings: [] }
      : scanGitHistory(root, gitRoot, {
          ...(options.history?.git !== undefined ? { git: options.history.git } : {}),
          ...(options.history?.limits ? { limits: options.history.limits } : {}),
          fingerprintKey,
          currentFingerprint: (fp) => currentFingerprints.has(fp),
        });
  currentFingerprints.clear();
  fingerprintKey.fill(0);

  // Firebase のセキュリティルール（このPCの中のファイル）
  const firebaseRules: ScanResult['firebaseRules'] = { files: [], findings: [] };
  for (const [path, kind] of [...rulesFiles.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    try {
      const ls = lstatSync(path);
      if (ls.isSymbolicLink() || !ls.isFile()) continue;
    } catch {
      continue;
    }
    const file = toRel(root, path);
    const text = safeRead(path, limits.maxFileBytes);
    if (text === undefined) {
      firebaseRules.files.push({ file, kind, parsed: false });
      continue;
    }
    add('firebase', file);
    const result = kind === 'database' ? analyzeDatabaseRules(text, now) : analyzeServiceRules(text, kind, now);
    firebaseRules.files.push({ file, kind, parsed: result.parsed });
    for (const f of result.findings) firebaseRules.findings.push({ ...f, file, kind });
  }

  const order: TechId[] = ['supabase', 'firebase', 'nextjs', 'expo', 'react-native', 'external-api', 'credentials', 'env'];
  const techs = order
    .filter((id) => evidence.has(id))
    .map((id) => ({ id, evidence: [...(evidence.get(id) ?? [])].slice(0, 10) }));

  return {
    root,
    rootName: basename(root) || root,
    techs,
    supabaseRefs: [...refs].sort(),
    envFiles,
    externalApis: [...externalApis.entries()].map(([name, via]) => ({ name, via })),
    secretNames,
    firebaseRules,
    privateKeys,
    publicExposures,
    gitHistory,
    rootPackageJson,
    stats,
  };
}
