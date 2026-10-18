// コードの中の「文字列の式」を、実行せずに読み取る（秘密鍵の本体を、連結・変数から復元するため）。
//
// 読めるもの：文字列リテラル（" ' `）・テンプレートリテラルの ${…}・+ での連結・配列の区切り（,）・
//             括弧・同じファイルの中で文字列だけを代入した定数（const A = "…" / A = "…"）
// 読まないもの：関数の呼び出しの結果・ほかのファイルから読み込んだ値・計算。eval やコードの実行はしない。
// 読めなかったものは、名前だけを unresolved に残す（「復元できない部分がある」という事実を捨てない）。
// 定数のたどりが上限（深さ・長さ）で打ち切られたときは limited にする（読み切れなかったことを、ダミーの根拠にしない）。
// 環境変数の参照（ENV_ROOT の形）は、値をコードに書かない正しい書き方なので、別に数える（envRefs）。

export interface StringExpr {
  /** 復元できた文字列（復元できなかった部分は空文字） */
  value: string;
  /** 復元できなかった変数・呼び出しの名前 */
  unresolved: string[];
  /** 環境変数の参照の数 */
  envRefs: number;
  /** 上限（定数をたどる深さ・式の長さ）で読み切れなかった */
  limited: boolean;
  /** 式の終わりの位置 */
  end: number;
}

const QUOTES = new Set(['"', "'", '`']);
const ENV_ROOT = /^(?:process\.env|import\.meta\.env|os\.environ|os\.getenv|Deno\.env|System\.getenv|ENV)(?:$|[.[(])/;
const IDENT_START = /[A-Za-z_$]/;
const MAX_DEPTH = 16;
const MAX_SPAN = 20000;

/** 空白・改行・コメントを飛ばす */
function skipSpace(t: string, i: number): number {
  while (i < t.length) {
    const c = t[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') i++;
    else if (c === '/' && t[i + 1] === '/') {
      const nl = t.indexOf('\n', i);
      i = nl < 0 ? t.length : nl + 1;
    } else if (c === '/' && t[i + 1] === '*') {
      const close = t.indexOf('*/', i + 2);
      i = close < 0 ? t.length : close + 2;
    } else break;
  }
  return i;
}

/** 対応する閉じ括弧の次の位置（引用符の中の括弧は数えない） */
function skipBalanced(t: string, i: number): number {
  const open = t[i];
  const close = open === '(' ? ')' : open === '[' ? ']' : '}';
  let depth = 0;
  for (let j = i; j < t.length && j - i < MAX_SPAN; j++) {
    const c = t[j] ?? '';
    if (QUOTES.has(c)) {
      for (j++; j < t.length && t[j] !== c; j++) if (t[j] === '\\') j++;
      continue;
    }
    if (c === open) depth++;
    else if (c === close && --depth === 0) return j + 1;
  }
  return t.length;
}

/** 同じファイルの中の定数（文字列だけを代入したもの）を引く。見つけた結果は覚えておく */
export class Constants {
  private readonly cache = new Map<string, StringExpr | null>();
  constructor(private readonly text: string) {}

  resolve(name: string, depth: number): StringExpr | undefined {
    if (!/^[A-Za-z_$][\w$]*$/.test(name)) return undefined;
    if (depth > MAX_DEPTH) return { value: '', unresolved: [name], envRefs: 0, end: 0, limited: true };
    if (this.cache.has(name)) return this.cache.get(name) ?? undefined;
    this.cache.set(name, null); // 自分自身を参照する定義で止まらないように
    const decl = new RegExp(`(?:^|[\\s;{(,])(?:(?:export\\s+)?(?:const|let|var)\\s+)?${name.replace(/\$/g, '\\$')}\\s*(?::[^=\\n;]{1,60})?=(?![=>])`, 'm').exec(this.text);
    if (!decl) return undefined;
    const start = skipSpace(this.text, decl.index + decl[0].length);
    const expr = readConcat(this.text, start, this, depth + 1);
    if (!expr) return undefined;
    this.cache.set(name, expr);
    return expr;
  }
}

/** 文字列リテラル（エスケープを戻す。テンプレートリテラルの ${…} も読む） */
function readLiteral(t: string, i: number, consts: Constants, depth: number): StringExpr {
  const quote = t[i];
  let out = '';
  const unresolved: string[] = [];
  let envRefs = 0;
  let limited = false;
  let j = i + 1;
  while (j < t.length && j - i < MAX_SPAN) {
    const c = t[j] ?? '';
    if (c === '\\') {
      const n = t[j + 1];
      if (n === undefined) break;
      if (n === 'n') out += '\n';
      else if (n === 'r' || n === 't' || n === '\n' || n === '\r') {
        // 改行コードの \r・タブ・行末の継続は、鍵の本体には関係しないので捨てる
      } else if (n === 'u' && /^[0-9a-fA-F]{4}$/.test(t.slice(j + 2, j + 6))) {
        out += String.fromCharCode(Number.parseInt(t.slice(j + 2, j + 6), 16));
        j += 6;
        continue;
      } else out += n;
      j += 2;
      continue;
    }
    if (c === quote) return { value: out, unresolved, envRefs, limited, end: j + 1 };
    if (quote === '`' && c === '$' && t[j + 1] === '{') {
      const inner = readConcat(t, skipSpace(t, j + 2), consts, depth);
      if (inner) {
        out += inner.value;
        unresolved.push(...inner.unresolved);
        envRefs += inner.envRefs;
        limited ||= inner.limited;
      }
      const close = t.indexOf('}', inner ? inner.end : j + 2);
      j = close < 0 ? t.length : close + 1;
      continue;
    }
    out += c;
    j++;
  }
  return { value: out, unresolved, envRefs, limited: limited || j - i >= MAX_SPAN, end: j };
}

/** 式の1つの要素（文字列リテラル・括弧・変数や呼び出し） */
function readOperand(t: string, i: number, consts: Constants, depth: number): StringExpr | undefined {
  const c = t[i] ?? '';
  if (QUOTES.has(c)) return readLiteral(t, i, consts, depth);
  if (c === '(') {
    const inner = readConcat(t, skipSpace(t, i + 1), consts, depth);
    return { value: inner?.value ?? '', unresolved: inner?.unresolved ?? [], envRefs: inner?.envRefs ?? 0, limited: inner?.limited ?? false, end: skipBalanced(t, i) };
  }
  if (!IDENT_START.test(c)) return undefined;
  // 変数名・プロパティ（a.b・a["b"]）・呼び出し（f(…)）をまとめて1つの要素として読む（中の文字列は値にしない）
  let j = i;
  let chain = '';
  let call = false;
  for (;;) {
    const m = /^[A-Za-z_$][\w$]*/.exec(t.slice(j, j + 200));
    if (!m) break;
    chain += m[0];
    j += m[0].length;
    const k = skipSpace(t, j);
    if (t[k] === '.' && IDENT_START.test(t[skipSpace(t, k + 1)] ?? '')) {
      chain += '.';
      j = skipSpace(t, k + 1);
      continue;
    }
    if (t[k] === '[') {
      chain += '[]';
      j = skipBalanced(t, k);
      if (t[skipSpace(t, j)] === '.') {
        j = skipSpace(t, skipSpace(t, j) + 1);
        chain += '.';
        continue;
      }
    }
    break;
  }
  const k = skipSpace(t, j);
  if (t[k] === '(') {
    call = true;
    j = skipBalanced(t, k);
  }
  if (ENV_ROOT.test(chain)) return { value: '', unresolved: [], envRefs: 1, limited: false, end: j };
  if (!call && /^[A-Za-z_$][\w$]*$/.test(chain)) {
    const v = consts.resolve(chain, depth);
    if (v) return { value: v.value, unresolved: v.unresolved, envRefs: v.envRefs, limited: v.limited, end: j };
  }
  return { value: '', unresolved: [call ? `${chain}()` : chain], envRefs: 0, limited: false, end: j };
}

/** + でつながった式を読む（式の終わり：; ) } など、+ 以外の記号・次の文） */
export function readConcat(t: string, i: number, consts: Constants, depth = 0): StringExpr | undefined {
  const first = readOperand(t, i, consts, depth);
  if (!first) return undefined;
  const out: StringExpr = { ...first, unresolved: [...first.unresolved] };
  for (;;) {
    const j = skipSpace(t, out.end);
    if (t[j] !== '+' || t[j + 1] === '+' || t[j + 1] === '=') break;
    const next = readOperand(t, skipSpace(t, j + 1), consts, depth);
    if (!next) break;
    out.value += next.value;
    out.unresolved.push(...next.unresolved);
    out.envRefs += next.envRefs;
    out.limited ||= next.limited;
    out.end = next.end;
  }
  return out;
}

/**
 * 秘密鍵の見出しを含む文字列リテラルから始まる式を、見出しの終わりの印（stop）が現れるか式が終わるまで読む。
 * 配列の要素（"-----BEGIN…", "MIIE…", …）や、改行をはさんだ連結も読む。
 */
export function readKeyExpression(t: string, quoteIndex: number, consts: Constants, stop: RegExp): StringExpr {
  const out: StringExpr = { value: '', unresolved: [], envRefs: 0, limited: false, end: quoteIndex };
  let i = quoteIndex;
  let needSeparator = false;
  while (i < t.length && i - quoteIndex < MAX_SPAN) {
    i = skipSpace(t, i);
    const c = t[i] ?? '';
    if (c === '+' || c === ',') {
      needSeparator = false;
      i++;
      continue;
    }
    if (c === '[' || c === ']') {
      i++;
      continue;
    }
    // 区切り（+ ,）なしで次の要素が来たら、別の文。そこで終わる
    if (needSeparator) break;
    const op = readOperand(t, i, consts, 0);
    if (!op) break;
    out.value += op.value;
    out.unresolved.push(...op.unresolved);
    out.envRefs += op.envRefs;
    out.limited ||= op.limited;
    out.end = op.end;
    i = op.end;
    needSeparator = true;
    if (stop.test(out.value)) break;
  }
  if (i - quoteIndex >= MAX_SPAN) out.limited = true;
  return out;
}

/** 見出しが、同じ行の文字列リテラルの中にあれば、その開き引用符の位置を返す（エスケープした引用符は数えない） */
export function openQuoteIndex(t: string, index: number): number | undefined {
  const lineStart = t.lastIndexOf('\n', index - 1) + 1;
  let open: number | undefined;
  for (let i = lineStart; i < index; i++) {
    const c = t[i] ?? '';
    if (open !== undefined) {
      if (c === '\\') i++;
      else if (c === t[open]) open = undefined;
    } else if (QUOTES.has(c)) {
      open = i;
    }
  }
  return open;
}
