// Firebase のセキュリティルール（このPCの中のルールファイル）を、明らかに危険な形だけ見分ける。
//
// 方針：
// ・ルールの意味は解析しない。次の決まった形だけを見る（それ以外は「判定しない」。危険とも安全とも言わない）
//     誰でも許可：if true／条件なしの allow／Realtime Database の true
//     期限付きのテストモード：request.time < timestamp.date(年, 月, 日)／"now < ミリ秒"
//     ログインしていれば誰でも：request.auth != null／"auth != null"
// ・このPCのファイルを見た結果で、Firebase に実際にデプロイされているルールとは限らない（画面でもそう伝える）
// ・ルールファイルの中身は外へ出さない。出すのは、ファイル名・行番号・match のパス・どの形だったかだけ

export type RulesKind = 'firestore' | 'storage' | 'database';

/**
 * open：誰でも許可／test-mode-active：期限付きのテストモード（期限前で、いまは誰でも許可）／
 * test-mode-expired：テストモードのまま（期限切れで、いまはこのルールでは拒否される）／auth-only：ログインしていれば誰でも
 */
export type RuleReason = 'open' | 'test-mode-active' | 'test-mode-expired' | 'auth-only';

export interface RuleFinding {
  line: number;
  severity: 'danger' | 'warn';
  reason: RuleReason;
  /** 読み取り・書き込みのどちらが許可されるか */
  access: 'read' | 'write' | 'read-write';
  /** all：データベース・ストレージ全体／path：一部のパスだけ */
  scope: 'all' | 'path';
  /** match のパス（Realtime Database は JSON の階層）。表示用 */
  path: string;
}

export interface RulesResult {
  /** ファイルの形を読み取れたか（読めなければ「判定できなかった」と表示する） */
  parsed: boolean;
  findings: RuleFinding[];
}

const WRITE_METHODS = new Set(['write', 'create', 'update', 'delete']);
const READ_METHODS = new Set(['read', 'get', 'list']);

/** コメントを空白に置き換える（行番号を変えないよう改行は残す。文字列の中の // は消さない） */
export function stripComments(text: string): string {
  let out = '';
  let i = 0;
  while (i < text.length) {
    const ch = text[i] ?? '';
    const next = text[i + 1] ?? '';
    if (ch === '"' || ch === "'") {
      let j = i + 1;
      while (j < text.length && text[j] !== ch && text[j] !== '\n') j += text[j] === '\\' ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j + 1;
    } else if (ch === '/' && next === '/') {
      while (i < text.length && text[i] !== '\n') {
        out += ' ';
        i++;
      }
    } else if (ch === '/' && next === '*') {
      const end = text.indexOf('*/', i + 2);
      const stop = end === -1 ? text.length : end + 2;
      out += text.slice(i, stop).replace(/[^\n]/g, ' ');
      i = stop;
    } else {
      out += ch;
      i++;
    }
  }
  return out;
}

function lineAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

/** 条件の形（決まった形でなければ undefined。判定しない） */
function conditionReason(cond: string | undefined, now: Date): RuleReason | undefined {
  if (cond === undefined) return 'open'; // allow read; のように条件がなければ、無条件に許可される
  let c = cond.replace(/\s+/g, '');
  while (c.startsWith('(') && c.endsWith(')')) c = c.slice(1, -1);
  if (c === 'true') return 'open';
  const t = /^request\.time<timestamp\.date\((\d{4}),(\d{1,2}),(\d{1,2})\)$/.exec(c);
  if (t) {
    const expires = Date.UTC(Number(t[1]), Number(t[2]) - 1, Number(t[3]));
    return now.getTime() < expires ? 'test-mode-active' : 'test-mode-expired';
  }
  if (/^(?:request\.auth(?:\.uid)?!=null|null!=request\.auth(?:\.uid)?)$/.test(c)) return 'auth-only';
  return undefined;
}

/** 重大度。決まった形でも、一部のパスだけの読み取りやログイン条件は、公開してよいデータかどうか判断が必要なので控えめにする */
function severityOf(reason: RuleReason, scope: 'all' | 'path', write: boolean): RuleFinding['severity'] | undefined {
  switch (reason) {
    case 'open':
    case 'test-mode-active':
      // 誰でも書き込める（消せる）→ 🔴。誰でも全体を読める → 🔴。一部のパスだけ誰でも読める → 公開してよいデータか確認（🟠）
      return write || scope === 'all' ? 'danger' : 'warn';
    case 'test-mode-expired':
      // 期限切れのテストモードは、いまはこのルールでは拒否される。ただし期限を延ばすだけで全開放に戻るので確認をすすめる
      return 'warn';
    case 'auth-only':
      // ログインすれば誰でも全体を読み書きできる → 🟠。一部のパスだけなら、ふつうの書き方なので数えない
      return scope === 'all' ? 'warn' : undefined;
  }
}

const accessOf = (read: boolean, write: boolean): RuleFinding['access'] => (read && write ? 'read-write' : write ? 'write' : 'read');

/** Cloud Firestore・Cloud Storage のルール（firestore.rules / storage.rules） */
export function analyzeServiceRules(text: string, kind: 'firestore' | 'storage', now: Date): RulesResult {
  const src = stripComments(text);
  if (!/\bservice\s+(?:cloud\.)?(?:firestore|firebase\.storage)\b/.test(src)) return { parsed: false, findings: [] };
  const findings: RuleFinding[] = [];
  const stack: (string | null)[] = []; // match のパス（match 以外の { は null）
  const re = /\bmatch\s+(\/\S*)\s*\{|\ballow\s+([a-z][a-z,\s]*?)\s*(?::\s*if\b([\s\S]*?))?\s*(?:;|(?=\n\s*(?:allow\b|match\b|\})))|\{|\}/g;
  for (const m of src.matchAll(re)) {
    const token = m[0];
    if (m[1] !== undefined) {
      stack.push(m[1]);
    } else if (m[2] !== undefined) {
      const methods = m[2].split(/[\s,]+/).filter(Boolean);
      if (methods.length === 0 || !methods.every((x) => READ_METHODS.has(x) || WRITE_METHODS.has(x))) continue;
      const reason = conditionReason(m[3], now);
      if (!reason) continue;
      const path = stack.filter((p): p is string => p !== null).join('');
      const all =
        kind === 'firestore'
          ? /^\/databases\/\{[^}]+\}\/documents\/\{[^}=]+=\*\*\}$/.test(path)
          : /^\/b\/\{[^}]+\}\/o\/\{[^}=]+=\*\*\}$/.test(path);
      const scope = all ? 'all' : 'path';
      const write = methods.some((x) => WRITE_METHODS.has(x));
      const read = methods.some((x) => READ_METHODS.has(x));
      const severity = severityOf(reason, scope, write);
      if (!severity) continue;
      findings.push({ line: lineAt(src, m.index ?? 0), severity, reason, access: accessOf(read, write), scope, path: path || '/' });
    } else if (token === '{') {
      stack.push(null);
    } else if (token === '}') {
      stack.pop();
    }
  }
  return { parsed: true, findings };
}

/** Realtime Database のルール（database.rules.json） */
export function analyzeDatabaseRules(text: string, now: Date): RulesResult {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    try {
      json = JSON.parse(stripComments(text)); // Realtime Database のルールにはコメントを書ける
    } catch {
      return { parsed: false, findings: [] };
    }
  }
  const rules = json && typeof json === 'object' ? (json as Record<string, unknown>).rules : undefined;
  if (!rules || typeof rules !== 'object' || Array.isArray(rules)) return { parsed: false, findings: [] };

  // 行番号：".read" / ".write" が出てくる順に、本文の中の位置を対応させる（目安）
  const seen = { '.read': 0, '.write': 0 };
  const lineOfNth = (key: '.read' | '.write', n: number): number => {
    let from = 0;
    for (let i = 0; i <= n; i++) {
      const at = text.indexOf(`"${key}"`, from);
      if (at === -1) return 1;
      if (i === n) return lineAt(text, at);
      from = at + 1;
    }
    return 1;
  };
  const reasonOf = (v: unknown): RuleReason | undefined => {
    if (v === true) return 'open';
    if (typeof v !== 'string') return undefined;
    const c = v.replace(/\s+/g, '');
    if (c === 'true') return 'open';
    const t = /^now<(\d{10,})$/.exec(c);
    if (t) return now.getTime() < Number(t[1]) ? 'test-mode-active' : 'test-mode-expired';
    if (/^(?:auth(?:\.uid)?!==?null|null!==?auth(?:\.uid)?)$/.test(c)) return 'auth-only';
    return undefined;
  };

  const findings: RuleFinding[] = [];
  const walk = (node: Record<string, unknown>, path: string[], depth: number) => {
    if (depth > 64) return;
    // 同じ階層の .read と .write が同じ形なら、1つにまとめる
    const perKey: { key: '.read' | '.write'; reason: RuleReason; line: number }[] = [];
    for (const [key, value] of Object.entries(node)) {
      if (key === '.read' || key === '.write') {
        const line = lineOfNth(key, seen[key]++);
        const reason = reasonOf(value);
        if (reason) perKey.push({ key, reason, line });
      } else if (value && typeof value === 'object' && !Array.isArray(value) && !key.startsWith('.')) {
        walk(value as Record<string, unknown>, [...path, key], depth + 1);
      }
    }
    const scope = path.length === 0 ? 'all' : 'path';
    const shown = path.length === 0 ? '/（全体）' : `/${path.join('/')}`;
    const byReason = new Map<RuleReason, typeof perKey>();
    for (const p of perKey) byReason.set(p.reason, [...(byReason.get(p.reason) ?? []), p]);
    for (const [reason, list] of byReason) {
      const write = list.some((p) => p.key === '.write');
      const read = list.some((p) => p.key === '.read');
      const severity = severityOf(reason, scope, write);
      if (!severity) continue;
      findings.push({ line: Math.min(...list.map((p) => p.line)), severity, reason, access: accessOf(read, write), scope, path: shown });
    }
  };
  walk(rules as Record<string, unknown>, [], 0);
  findings.sort((a, b) => a.line - b.line);
  return { parsed: true, findings };
}

/** ルールファイルの既定の名前（firebase.json で別の名前が指定されていれば、それも読む） */
export const DEFAULT_RULES_FILES: Record<string, RulesKind> = {
  'firestore.rules': 'firestore',
  'storage.rules': 'storage',
  'database.rules.json': 'database',
};

/** firebase.json に書かれた、ルールファイル・公開フォルダ（Hosting）の場所（firebase.json からの相対パス） */
export function firebaseJsonPaths(text: string): { rules: { path: string; kind: RulesKind }[]; hostingPublic: string[] } {
  const out = { rules: [] as { path: string; kind: RulesKind }[], hostingPublic: [] as string[] };
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return out;
  }
  if (!json || typeof json !== 'object') return out;
  const o = json as Record<string, unknown>;
  const list = (v: unknown): Record<string, unknown>[] =>
    (Array.isArray(v) ? v : [v]).filter((x): x is Record<string, unknown> => !!x && typeof x === 'object');
  for (const [key, kind] of [['firestore', 'firestore'], ['storage', 'storage'], ['database', 'database']] as const) {
    for (const entry of list(o[key])) if (typeof entry.rules === 'string') out.rules.push({ path: entry.rules, kind });
  }
  for (const entry of list(o.hosting)) if (typeof entry.public === 'string') out.hostingPublic.push(entry.public);
  return out;
}
