// 秘密情報を探す共通の仕組み。サービスごとの違いは定義データ（secret-defs.ts）にだけ書き、ここには専用の処理を増やさない。
//
// 探し方：
//   1. 名前：定義の環境変数名（公開用の接頭辞付きも含む）が、.env 系・設定ファイル・ソースコードのどこにあるか
//   2. 値の形：接頭辞が公式に決まっていて取り違えようがない形式（sb_secret_・ghp_ など）は、名前がなくても探す
// 見つけた場所ごとに「ファイル・行番号・書き方・値の分類」だけを返す。値は表示しない・保持しない。
// 値を見るのは、直書きか参照か、本物らしいかを見分けるためだけで、判定が終わったら捨てる。

import { PUBLIC_ENV_PREFIXES } from './env.js';
import { classifyKeyBody, pemBodyLines } from './key-structure.js';
import { SECRET_DEFINITIONS, type SecretDefinition, type ValueCheck } from './secret-defs.js';

/** 見つけた場所の種類 */
export type SecretPlace = 'env' | 'env-example' | 'config' | 'source' | 'other';

/**
 * 書き方の種類
 *   public-env：公開用の接頭辞（NEXT_PUBLIC_ など）付きの名前に値がある（アプリに埋め込まれる）
 *   literal：値そのものが書かれている（直書き）
 *   env-value：.env に値が書かれている（.env の本来の使い方）
 *   reference：環境変数・シークレットを参照しているだけ（値は書かれていない）
 *   empty：名前だけで、値が空
 */
export type SecretUsage = 'public-env' | 'literal' | 'env-value' | 'reference' | 'empty';

/**
 * 値の分類（値そのものは持たない）
 *   real-like：本物の形式に見える
 *   test-like：形式は似ているが、テスト用・ローカル開発用と判断した
 *   placeholder：見本の値・形式が違う
 *   public：公開してよいキー（Supabase の publishable / anon など）
 *   uncertain：本物か、ローカル開発用などの安全なものか判断できない（安全とは扱わず「要確認」にする）
 */
export type SecretValueKind = 'real-like' | 'test-like' | 'placeholder' | 'public' | 'uncertain';
export type SecretValueReason =
  | 'token-format'
  | 'url-credentials'
  | 'private-key'
  | 'key-unverified'
  | 'test-word'
  | 'too-short'
  | 'low-randomness'
  | 'local-dev'
  | 'local-unconfirmed'
  | 'placeholder-pattern'
  | 'not-token-format'
  | 'no-credentials'
  | 'public-key';

export interface SecretValue {
  kind: SecretValueKind;
  reason: SecretValueReason;
  /** public のとき：どの公開キーか */
  publicLabel?: string;
}

export interface SecretNameHit {
  /** 定義の id（secret-defs.ts） */
  defId: string;
  /** 見つけたときの変数名。値の形で見つけた場合は空 */
  as: string;
  file: string;
  line: number;
  place: SecretPlace;
  usage: SecretUsage;
  /** 値が書かれている場合だけ */
  value?: SecretValue;
  /** 公開してよいキーの変数名（SUPABASE_ANON_KEY など）で見つけたか */
  publicName?: boolean;
  /** 同じファイルに、ローカルの Supabase の URL（localhost / 127.0.0.1）が書かれているか（ローカル開発用の判断の根拠の1つ） */
  localHint?: boolean;
}

/** ローカルの Supabase（supabase start）の URL が書かれているか */
export function hasLocalSupabaseUrl(text: string): boolean {
  return /(?:localhost|127\.0\.0\.1):54321\b/.test(text) || /SUPABASE[A-Z_]*URL["']?\s*[=:]\s*["']?https?:\/\/(?:localhost|127\.0\.0\.1)\b/.test(text);
}

/** アプリに埋め込まれる変数名の接頭辞か（NEXT_PUBLIC_ など。env.ts と同じ一覧） */
const isPublicPrefix = (prefix: string) => PUBLIC_ENV_PREFIXES.includes(prefix);

/** テスト用の値によく使われる語 */
const TEST_WORDS = /test|fake|dummy|mock|example|sample|placeholder|canary|fixture|redacted|invalid|not[-_]?a[-_]?real|changeme|your[-_]|xxxx/i;

// ───────────── 値の分類（共通） ─────────────

/** 文字の偏り（1文字あたりのビット数）。ランダムな文字列ほど大きい */
function entropy(text: string): number {
  const counts = new Map<string, number>();
  for (const ch of text) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / text.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** ランダムな文字列に見えるか（16進数だけの値と、英大小文字・数字が混ざる値で基準を変える） */
function looksRandom(text: string): boolean {
  if (/(.)\1{5,}/.test(text)) return false;
  // 1234・abcd のような並びは、手で作った短い値の印。長い本物のトークン（ID を含む GitHub の新形式など）にも偶然入りうるので、短い値だけで見る
  if (text.length < 60 && /(0123|1234|2345|abcd|ABCD)/.test(text)) return false;
  if (/^[0-9a-f]+$/.test(text)) return /\d/.test(text) && /[a-f]/.test(text) && entropy(text) >= 3.2;
  return /[A-Z]/.test(text) && /[a-z]/.test(text) && /\d/.test(text) && entropy(text) >= 4;
}

function isPlaceholderText(v: string): boolean {
  return v.length < 8 || /^(<.*>|\[.*\]|\*+|x+|\.+|-+)$/i.test(v) || /^(your|my)[-_]/i.test(v) || /\.\.\.|…/.test(v);
}

function decodeJwtPayload(v: string): Record<string, unknown> | undefined {
  const parts = v.split('.');
  if (parts.length !== 3 || !parts[1] || !v.startsWith('eyJ')) return undefined;
  try {
    const payload: unknown = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    return payload && typeof payload === 'object' ? (payload as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

const LOCAL_HOSTS = /^(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|\[::1\]|host\.docker\.internal|db|postgres|mysql|database|.*\.local)$/i;
const PLACEHOLDER_PASSWORD = /^(\[.*\]|<.*>|\{.*\}|\$.*|\*+|x+|pass(word)?|secret|changeme|postgres|root|admin|your[-_].*|.*password.*|\.\.\.|…)$/i;

/** 1つの確かめ方で分類する。当てはまらなければ undefined */
function runCheck(check: ValueCheck, v: string): SecretValue | undefined {
  switch (check.type) {
    case 'token': {
      const m = check.pattern.exec(v);
      if (!m) return undefined;
      const random = m[1] ?? '';
      if (TEST_WORDS.test(v)) return { kind: 'test-like', reason: 'test-word' };
      if (random.length < check.minRandom) return { kind: 'test-like', reason: 'too-short' };
      if (!looksRandom(random)) return { kind: 'test-like', reason: 'low-randomness' };
      return { kind: 'real-like', reason: 'token-format' };
    }
    case 'jwt-role': {
      const payload = decodeJwtPayload(v);
      const role = typeof payload?.role === 'string' ? payload.role : undefined;
      if (!role) return undefined;
      if (check.publicRoles.includes(role)) return { kind: 'public', reason: 'public-key', publicLabel: `${role} キー（公開してよいキー）` };
      if (!check.secretRoles.includes(role)) return undefined;
      // Supabase のローカル開発用（supabase start）の鍵は iss が supabase-demo。ただし iss だけでは安全とせず、
      // 「要確認」にしておき、ほかの根拠（ローカルの URL・supabase/config.toml）がそろったときだけ scan.ts でローカル用とする
      if (payload?.iss === 'supabase-demo') return { kind: 'uncertain', reason: 'local-unconfirmed' };
      if (TEST_WORDS.test(JSON.stringify(payload))) return { kind: 'test-like', reason: 'test-word' };
      return { kind: 'real-like', reason: 'token-format' };
    }
    case 'opaque': {
      if (!(check.charset ?? /^[A-Za-z0-9_-]+$/).test(v)) return undefined;
      if (TEST_WORDS.test(v)) return { kind: 'test-like', reason: 'test-word' };
      if (v.length < check.minLength) return { kind: 'test-like', reason: 'too-short' };
      if (check.maxLength !== undefined && v.length > check.maxLength) return undefined;
      const random = v.replace(/^[a-z]{2,3}_/, ''); // sk_ などの短い接頭辞は除いて調べる
      if (!looksRandom(random)) return { kind: 'test-like', reason: 'low-randomness' };
      return { kind: 'real-like', reason: 'token-format' };
    }
    case 'url-credentials': {
      const m = /^([a-z][a-z0-9+.-]*):\/\/([^:@/\s]*)(?::([^@/\s]*))?@(\[[^\]]+\]|[^/:?#\s]+)/i.exec(v);
      if (!m) return /^[a-z][a-z0-9+.-]*:\/\//i.test(v) ? { kind: 'placeholder', reason: 'no-credentials' } : undefined;
      let password = m[3] ?? '';
      try {
        password = decodeURIComponent(password);
      } catch {
        // そのまま
      }
      const host = m[4] ?? '';
      if (!password) return { kind: 'placeholder', reason: 'no-credentials' };
      if (PLACEHOLDER_PASSWORD.test(password) || isPlaceholderText(password) || TEST_WORDS.test(password)) return { kind: 'placeholder', reason: 'placeholder-pattern' };
      if (LOCAL_HOSTS.test(host)) return { kind: 'test-like', reason: 'local-dev' };
      return { kind: 'real-like', reason: 'url-credentials' };
    }
    case 'pem-private-key': {
      const text = v.replace(/\\n/g, '\n');
      const m = /-----BEGIN ([A-Z ]*)PRIVATE KEY-----([\s\S]*?)-----END/.exec(text);
      if (!m) return undefined;
      // 鍵の本体は、語ではなく構造で判定する（本物の鍵にも test などの並びが偶然含まれるため）。見出し行（Proc-Type など）は除く
      // コードの文字列リテラルとして連結して書いた鍵も、引用符の内側だけをつないで本体を取り出す
      const lines = pemBodyLines(text, m.index, m[2] ?? '');
      // Proc-Type の見出しは、カンマの有無を問わない
      const legacyEncrypted = lines.some((l) => /^Proc-Type:4,?ENCRYPTED/i.test(l)) && !/ENCRYPTED|OPENSSH/.test(m[1] ?? '');
      const body = lines.filter((l) => !l.includes(':')).join('');
      const judged = classifyKeyBody(legacyEncrypted ? 'legacy-encrypted' : (m[1] ?? ''), body);
      if (judged.value === 'real-like') return { kind: 'real-like', reason: 'private-key' };
      if (judged.value === 'uncertain') return { kind: 'uncertain', reason: 'key-unverified' };
      return { kind: 'test-like', reason: body.length < 40 ? 'too-short' : 'not-token-format' };
    }
  }
}

/**
 * 値が、その定義の秘密情報として本物らしいかを分類する。値はこの関数の外へ出さない（分類と理由だけを返す）。
 * フォルダ名（tests など）では判断しない。値の形だけで判断する。
 */
/** 重い順（JSON などに複数入っているとき、いちばん重いものを結果にする） */
const KIND_ORDER: SecretValueKind[] = ['real-like', 'uncertain', 'test-like', 'public', 'placeholder'];

/** JSON・配列の中の文字列を取り出す（SUPABASE_SECRET_KEYS などの新方式の変数） */
function stringLeaves(v: string): string[] | undefined {
  if (!/^[[{]/.test(v)) return undefined;
  const out: string[] = [];
  const walk = (x: unknown) => {
    if (typeof x === 'string') out.push(x);
    else if (Array.isArray(x)) x.forEach(walk);
    else if (x && typeof x === 'object') Object.values(x).forEach(walk);
  };
  try {
    walk(JSON.parse(v));
  } catch {
    // JSON として読めなければ、引用符で囲まれた部分を取り出す
    for (const m of v.matchAll(/["']([^"'\r\n]{8,})["']/g)) out.push(m[1] ?? '');
  }
  return out.slice(0, 50);
}

export function classifySecretValue(def: SecretDefinition, value: string): SecretValue {
  const v = value.trim();
  // JSON などにまとめて入っている場合は、中の値ごとに分類し、いちばん重いものを返す（値そのものは返さない）
  const leaves = def.checks.some((c) => c.type === 'pem-private-key') ? undefined : stringLeaves(v);
  if (leaves) {
    const results = leaves.map((x) => classifySecretValue(def, x));
    results.sort((a, b) => KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind));
    return results[0] ?? { kind: 'placeholder', reason: 'placeholder-pattern' };
  }
  for (const pub of def.publicLookalikes) if (pub.pattern.test(v)) return { kind: 'public', reason: 'public-key', publicLabel: pub.label };
  if (!def.checks.some((c) => c.type === 'pem-private-key' || c.type === 'url-credentials') && isPlaceholderText(v)) {
    return { kind: 'placeholder', reason: 'placeholder-pattern' };
  }
  for (const check of def.checks) {
    const r = runCheck(check, v);
    if (r) return r;
  }
  return { kind: 'placeholder', reason: isPlaceholderText(v) ? 'placeholder-pattern' : 'not-token-format' };
}

// ───────────── 名前の照合 ─────────────

/** 定義の環境変数名（秘密のキーの名前と、公開してよいキーの名前） */
function namesOf(def: SecretDefinition): { name: string; publicName: boolean }[] {
  return [
    ...[...def.envNames, ...(def.codeNames ?? [])].map((name) => ({ name, publicName: false })),
    ...(def.publicEnvNames ?? []).map((name) => ({ name, publicName: true })),
  ];
}

/** 変数名がどの定義に当たるか（公開用の接頭辞付きも含む）。長い名前を先に照合する（SUPABASE_SECRET_KEYS と SUPABASE_SECRET_KEY など） */
function matchName(key: string): { def: SecretDefinition; prefix: string; publicName: boolean } | undefined {
  for (const def of SECRET_DEFINITIONS) {
    for (const { name, publicName } of namesOf(def).sort((a, b) => b.name.length - a.name.length)) {
      if (!key.endsWith(name)) continue;
      const prefix = key.slice(0, key.length - name.length);
      if (prefix === '' || isPublicPrefix(prefix)) return { def, prefix, publicName };
    }
  }
  return undefined;
}

/** 公開してよいキーの変数名で見つけたものを、数える対象にするか（秘密の値・公開キーが入っている場合だけ。参照や空は数えない） */
function keepPublicNameHit(hit: SecretNameHit): boolean {
  return hit.value !== undefined && hit.value.kind !== 'placeholder';
}

/** 参照の書き方（$X・${X}・${{ secrets.X }}・{{ … }}） */
function isReferenceValue(value: string): boolean {
  return value.startsWith('$') || value.includes('${') || value.includes('{{');
}

/**
 * ソース・設定ファイルで、名前の直後に値そのものが書かれているか。
 * process.env の参照・Deno.env.get("X")・os.environ["X"]・${{ secrets.X }} のような参照は reference。
 */
function valueAfterName(after: string, def: SecretDefinition): { usage: 'literal' | 'reference' | 'empty'; value?: string } {
  // 例：  NAME = "…" ／ "NAME": "…" ／ ['NAME'] = '…' ／ NAME: '…'（YAML）
  const quoted = /^["'`]?\]?\s*[:=]\s*(["'`])((?:(?!\1)[^\r\n])*)\1/.exec(after);
  if (quoted) {
    const value = quoted[2] ?? '';
    if (value === '') return { usage: 'empty' };
    if (isReferenceValue(value)) return { usage: 'reference' };
    return { usage: 'literal', value };
  }
  // PEM の秘密鍵は複数行のことがあるため、名前のあとをまとめて渡す
  if (def.checks.some((c) => c.type === 'pem-private-key') && /^["'`]?\]?\s*[:=]\s*["'`|>]?\s*-----BEGIN/.test(after)) {
    return { usage: 'literal', value: after };
  }
  // 引用符のない値（シェル・YAML）は、定義の形式に当てはまるときだけ値とみなす（それ以外はコードの式の可能性が高い）
  const bare = /^["'`]?\]?\s*[:=]\s*([^\s"'`,;)}\]]+)/.exec(after);
  if (bare) {
    const value = bare[1] ?? '';
    const c = classifySecretValue(def, value);
    if (c.kind === 'real-like' || c.kind === 'test-like' || c.kind === 'public') return { usage: 'literal', value };
  }
  return { usage: 'reference' };
}

function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

/**
 * 見つけた値を受け取る関数（同じ秘密情報かどうかを、値を残さずに比べるため。Git の履歴のチェックで使う）。
 * 値は、この関数の呼び出しの中だけで使い、結果には入れない
 */
export type ValueSink = (hit: SecretNameHit, value: string) => void;

/** 検出結果に対応する値を、関数の外へ出さずに渡す（hits に残ったものだけ） */
function deliver(hits: SecretNameHit[], values: Map<SecretNameHit, string>, onValue: ValueSink | undefined): SecretNameHit[] {
  if (onValue) for (const h of hits) {
    const v = values.get(h);
    if (v !== undefined) onValue(h, v);
  }
  values.clear();
  return hits;
}

/** 値の形で見つけたものを、名前で見つけたものと重ねずに加える */
function addShapeHits(text: string, file: string, place: SecretPlace, usage: SecretUsage, hits: SecretNameHit[], values: Map<SecretNameHit, string>): void {
  for (const def of SECRET_DEFINITIONS) {
    if (!def.shapeInText) continue;
    for (const m of text.matchAll(def.shapeInText)) {
      const index = m.index ?? 0;
      const before = index > 0 ? text[index - 1] ?? '' : '';
      if (/[A-Za-z0-9_-]/.test(before)) continue; // 長い文字列の途中は対象外
      const line = lineOf(text, index);
      if (hits.some((h) => h.file === file && h.line === line && h.defId === def.id)) continue;
      const value = classifySecretValue(def, m[0]);
      // 名前のない場所では、公開キー・形式違いは数えない（JWT の anon キーなど）
      if (value.kind !== 'real-like' && value.kind !== 'test-like' && value.kind !== 'uncertain') continue;
      const hit: SecretNameHit = { defId: def.id, as: '', file, line, place, usage, value, localHint: hasLocalSupabaseUrl(text) };
      values.set(hit, m[0]);
      hits.push(hit);
      if (hits.length >= 200) return;
    }
  }
}

// ───────────── 探す ─────────────

/** .env 系ファイルの中を探す */
export function findInEnv(text: string, file: string, isExample: boolean, onValue?: ValueSink): SecretNameHit[] {
  const hits: SecretNameHit[] = [];
  const values = new Map<SecretNameHit, string>();
  const place: SecretPlace = isExample ? 'env-example' : 'env';
  const localHint = hasLocalSupabaseUrl(text);
  const lines = text.split(/\r?\n/);
  lines.forEach((raw, i) => {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(raw);
    if (!m?.[1]) return;
    const key = m[1];
    let value = (m[2] ?? '').trim();
    if ((value.startsWith('"') && value.endsWith('"') && value.length > 1) || (value.startsWith("'") && value.endsWith("'") && value.length > 1)) value = value.slice(1, -1);
    else if (/^["']-----BEGIN/.test(value)) value = lines.slice(i).join('\n').slice(1, 8000); // 複数行の秘密鍵
    else value = value.replace(/\s+#.*$/, '');
    const isPublicName = PUBLIC_ENV_PREFIXES.some((p) => key.startsWith(p));
    const usageFor = (prefixed: boolean): SecretUsage => (prefixed ? 'public-env' : isExample ? 'literal' : 'env-value');

    const named = matchName(key);
    if (named) {
      const hit: SecretNameHit = { defId: named.def.id, as: key, file, line: i + 1, place, usage: 'empty', localHint };
      if (value !== '' && !isReferenceValue(value)) {
        hit.value = classifySecretValue(named.def, value);
        values.set(hit, value);
        // 公開してよいキーの欄に秘密の値が入っていたら、公開されるものとして扱う
        hit.usage = usageFor(named.prefix !== '' || (named.publicName && hit.value.kind !== 'public'));
      }
      if (named.publicName) {
        hit.publicName = true;
        if (!keepPublicNameHit(hit)) return;
      }
      hits.push(hit);
      return;
    }
    // 定義の名前ではない変数でも、値の形が決まっている秘密情報なら見つける（例：MY_KEY=sb_secret_…）
    if (value === '' || isReferenceValue(value)) return;
    for (const def of SECRET_DEFINITIONS) {
      if (!def.shapeInText) continue;
      const re = new RegExp(`^(?:${def.shapeInText.source})$`);
      if (!re.test(value)) continue;
      const v = classifySecretValue(def, value);
      if (v.kind !== 'real-like' && v.kind !== 'test-like' && v.kind !== 'uncertain') continue;
      const hit: SecretNameHit = { defId: def.id, as: key, file, line: i + 1, place, usage: usageFor(isPublicName), value: v, localHint };
      values.set(hit, value);
      hits.push(hit);
      return;
    }
  });
  return deliver(hits, values, onValue);
}

/** 設定ファイル・ソースコードの中を探す */
export function findInText(text: string, file: string, place: 'config' | 'source' | 'other', onValue?: ValueSink): SecretNameHit[] {
  const values = new Map<SecretNameHit, string>();
  return deliver(findInTextInner(text, file, place, values), values, onValue);
}

function findInTextInner(text: string, file: string, place: 'config' | 'source' | 'other', values: Map<SecretNameHit, string>): SecretNameHit[] {
  const hits: SecretNameHit[] = [];
  const localHint = hasLocalSupabaseUrl(text);
  for (const def of SECRET_DEFINITIONS) {
    for (const { name: n, publicName } of namesOf(def)) {
      if (!text.includes(n)) continue;
      const re = new RegExp(`([A-Za-z0-9_]*)${n}(?![A-Za-z0-9_])`, 'g');
      for (const m of text.matchAll(re)) {
        const prefix = m[1] ?? '';
        if (prefix !== '' && !isPublicPrefix(prefix)) continue; // 別の変数名（MY_GITHUB_TOKEN など）
        const index = m.index ?? 0;
        const after = text.slice(index + m[0].length, index + m[0].length + (def.checks.some((c) => c.type === 'pem-private-key') ? 8000 : 400));
        const found = valueAfterName(after, def);
        const hit: SecretNameHit = { defId: def.id, as: prefix + n, file, line: lineOf(text, index), place, usage: found.usage, localHint };
        if (found.value !== undefined) {
          hit.value = classifySecretValue(def, found.value);
          values.set(hit, found.value);
          if (prefix !== '' || (publicName && hit.value.kind !== 'public')) hit.usage = 'public-env';
        }
        if (publicName) {
          hit.publicName = true;
          if (!keepPublicNameHit(hit)) continue;
        }
        hits.push(hit);
        if (hits.length >= 200) return hits;
      }
    }
  }
  addShapeHits(text, file, place, 'literal', hits, values);
  return hits;
}

const CONFIG_EXT = /\.(json|jsonc|ya?ml|toml|ini|cfg|conf|properties|plist|xml)$/i;
const SOURCE_EXT = /\.(m?[jt]sx?|c[jt]s|vue|svelte|astro|py|rb|go|java|kt|kts|swift|dart|php|rs|cs|sh|bash|zsh|ps1|bat|cmd)$/i;
const SKIP_FILES = new Set(['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'composer.lock', 'Podfile.lock', 'Cargo.lock']);

/** 中身を探す対象のファイルか（.env 系は別に扱う） */
export function textPlaceOf(name: string): 'config' | 'source' | undefined {
  if (SKIP_FILES.has(name)) return undefined;
  if (/^Dockerfile/i.test(name) || /^docker-compose/i.test(name) || /^\.npmrc$|^\.mcp\.json$/i.test(name)) return 'config';
  // AWS の共有認証情報ファイル（~/.aws/credentials と同じ形式。aws_secret_access_key = … と書かれる）
  if (name === 'credentials') return 'config';
  if (CONFIG_EXT.test(name)) return 'config';
  if (SOURCE_EXT.test(name)) return 'source';
  return undefined;
}
