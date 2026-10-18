// 秘密鍵・認証情報のファイルと、公開フォルダ（public/・static/ など）に入ると危険なファイルを、中身で見分ける。
//
// 方針：
// ・ファイル名や拡張子だけでは判定しない（.pem には公開してよい証明書もある）。中身の形が公式の形式に当てはまるものだけ
// ・本物らしさは、鍵の本体が正しい形（base64 を戻すと ASN.1 / openssh-key-v1 の形）かどうかで確かめる。形が崩れたダミーは数えない
// ・鍵の本体に「test」「fake」などの語が含まれるかでは判定しない（本物の鍵にも偶然含まれるため。src/detect/key-structure.ts）
// ・本物か判断できないものは、安全とは扱わず uncertain（確認をおすすめ）にする
// ・鍵・値は外へ出さない。返すのは種類・行番号・暗号化の有無だけ

import { classifyKeyBody, type KeyBodyValue } from './key-structure.js';
import { Constants, openQuoteIndex, readKeyExpression } from './string-expr.js';

/** pem：PKCS#1/#8・EC などの PEM／openssh：OpenSSH 形式／pgp：PGP の秘密鍵／putty：PuTTY の鍵／service-account：Google・Firebase のサービスアカウント鍵 */
export type PrivateKeyKind = 'pem' | 'openssh' | 'pgp' | 'putty' | 'service-account';

export interface PrivateKeyMatch {
  kind: PrivateKeyKind;
  /** real-like：本物の鍵の構造／test-like：はっきりしたダミー（見本の文字・同じ値の繰り返し）／uncertain：本物か判断できない */
  value: KeyBodyValue;
  /** パスフレーズで暗号化されている */
  encrypted: boolean;
  line: number;
  /** 「-----BEGIN」などの見出しの位置（ファイルの中の文字の位置。同じ行の複数の鍵を見分けるため） */
  index: number;
  /** 鍵を組み立てる式に、復元できない部分（変数・呼び出し）がある */
  unresolved?: boolean;
}

// OAuth クライアントの秘密（client_secret.json）の見本の値を見分けるための語（鍵の本体の判定には使わない）
const TEST_WORDS = /test|fake|dummy|mock|example|sample|placeholder|redacted|invalid|not[-_]?a[-_]?real|changeme|your[-_]|xxxx/i;

function lineAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

/** 1つのファイルから取り出した秘密鍵の候補（本体は結果に入れない。指紋づくり・名前つきの検出との突き合わせだけに使う） */
export interface PrivateKeyCandidate extends PrivateKeyMatch {
  /** 復元できた鍵の本体（外へ出さない） */
  body: string;
}

const PEM_BEGIN = /-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?)PRIVATE KEY-----/g;
const MAX_KEYS_PER_FILE = 20;

/**
 * 復元できない部分（変数・呼び出し）がある鍵の判定。
 * 構造が正しく本物と分かればそのまま。そうでなくても、引用符の中に鍵の本体らしい断片（base64・十分な長さ・ランダム）が
 * 書かれていれば、本物の鍵の一部の可能性があるので、ダミーとは扱わず uncertain（確認をおすすめ）にする。
 * 断片が見本の文字（base64 として読めない）なら、ダミーのまま。断片がない（見出しと変数だけ）なら、鍵をコードに書いた証拠がないので数えない。
 * ただし、同じファイルの定数を上限まで読んでも読み切れなかった（limited）ときは、本体がその先にある可能性があるので、断片がなくても uncertain にする。
 */
function judgePartial(value: KeyBodyValue, body: string, limited: boolean): KeyBodyValue {
  if (value !== 'test-like') return value;
  if (limited && /^[A-Za-z0-9+/=]*$/.test(body)) return 'uncertain';
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(body) || body.length < 24) return value;
  return new Set(body).size >= 12 ? 'uncertain' : value;
}

/** PEM の本体の行から、判定・暗号化の有無を決める */
function judgePem(label: string, lines: string[], partial: boolean, limited = false): { value: KeyBodyValue; encrypted: boolean; body: string } {
  // 古い暗号化 PEM（Proc-Type: 4,ENCRYPTED）の見出し行は除く（カンマの有無は問わない）
  const encrypted = label === 'ENCRYPTED ' || lines.some((l) => /^Proc-Type:4,?ENCRYPTED/i.test(l));
  const body = lines.filter((l) => !l.includes(':')).join('');
  // 古い形式の暗号化 PEM（Proc-Type）は、本体が暗号文なので ASN.1 の形にはならない
  const judged = classifyKeyBody(encrypted && label !== 'ENCRYPTED ' && label !== 'OPENSSH ' ? 'legacy-encrypted' : label, body);
  const value = partial ? judgePartial(judged.value, body, limited) : judged.value;
  return { value, encrypted: encrypted || judged.encrypted === true, body };
}

/** PEM の秘密鍵の候補をすべて取り出す（ふつうの PEM・コードの文字列の式・.env や JSON の "\n" の書き方） */
function pemCandidates(text: string): PrivateKeyCandidate[] {
  const out: PrivateKeyCandidate[] = [];
  let consts: Constants | undefined;
  let searchFrom = 0;
  for (const m of text.matchAll(PEM_BEGIN)) {
    const index = m.index ?? 0;
    if (index < searchFrom) continue; // 前の鍵の中
    const label = m[1] ?? '';
    const endMark = `-----END ${label}PRIVATE KEY-----`;
    const quote = openQuoteIndex(text, index);
    let lines: string[] | undefined;
    let partial = false;
    let unresolved = false;
    let limited = false;
    if (quote !== undefined) {
      // コードの文字列リテラルの中：式を実行せずに読み、連結・同じファイルの定数を復元する
      consts ??= new Constants(text);
      const expr = readKeyExpression(text, quote, consts, new RegExp(endMark));
      const begin = expr.value.indexOf(m[0]);
      const end = expr.value.indexOf(endMark, begin + m[0].length);
      unresolved = expr.unresolved.length > 0 || expr.limited;
      limited = expr.limited;
      if (begin < 0) continue;
      if (end < 0 && !unresolved) continue; // 終わりの印がなく、復元できない部分もない（鍵ではない文字列）
      lines = expr.value.slice(begin + m[0].length, end < 0 ? undefined : end).split('\n').map((l) => l.replace(/\s/g, ''));
      partial = unresolved || end < 0;
      searchFrom = expr.end;
    } else {
      // ふつうの PEM（.env の 1行の値・JSON の "\n" も、改行として読む）。base64 の + には触れない
      const end = text.indexOf(endMark, index + m[0].length);
      if (end < 0) continue;
      lines = text
        .slice(index + m[0].length, end)
        .replace(/\\r\\n|\\n/g, '\n')
        .split('\n')
        .map((l) => l.replace(/[\s\\]/g, ''));
      searchFrom = end + endMark.length;
    }
    const judged = judgePem(label, lines, partial, limited);
    const candidate: PrivateKeyCandidate = {
      kind: label === 'OPENSSH ' ? 'openssh' : 'pem',
      value: judged.value,
      encrypted: judged.encrypted,
      line: lineAt(text, index),
      index,
      body: judged.body,
    };
    if (unresolved) candidate.unresolved = true;
    out.push(candidate);
    if (out.length >= MAX_KEYS_PER_FILE) break;
  }
  return out;
}

/**
 * 文字列の中の秘密鍵の候補をすべて探す（同じファイルに複数あっても、それぞれを返す）。
 * サービスアカウント鍵（JSON）・PEM・PGP・PuTTY。本体は外へ出さない（指紋・突き合わせ用に呼び出し側へ渡すだけ）
 */
export function findPrivateKeyCandidates(text: string): PrivateKeyCandidate[] {
  if (!/PRIVATE KEY|PuTTY-User-Key-File|service_account/.test(text)) return [];

  // サービスアカウント鍵（JSON）：type が service_account で、private_key に秘密鍵が入っている
  if (/"type"\s*:\s*"service_account"/.test(text)) {
    try {
      const json: unknown = JSON.parse(text);
      const o = json && typeof json === 'object' ? (json as Record<string, unknown>) : undefined;
      if (o?.type === 'service_account' && typeof o.private_key === 'string') {
        const inner = findPrivateKeyCandidates(o.private_key)[0];
        const at = Math.max(0, text.indexOf('"private_key"'));
        if (inner) return [{ ...inner, kind: 'service-account', line: lineAt(text, at), index: at }];
      }
    } catch {
      // JSON として読めなければ、下の PEM の判定に任せる
    }
  }

  const out = pemCandidates(text);
  if (out.length > 0) return out;

  const normalized = text.replace(/\\r\\n|\\n/g, '\n');
  const pgp = /-----BEGIN PGP PRIVATE KEY BLOCK-----([\s\S]*?)-----END PGP PRIVATE KEY BLOCK-----/.exec(normalized);
  if (pgp) {
    const lines = (pgp[1] ?? '').split('\n').map((l) => l.trim()).filter((l) => l && !l.includes(':'));
    // ASCII armor の最後の「=」で始まる行は、チェックサム（CRC-24）
    const crcLine = lines.length > 1 && /^=[A-Za-z0-9+/]{4}$/.test(lines[lines.length - 1] ?? '') ? lines.pop() : undefined;
    const body = lines.join('');
    const judged = classifyKeyBody('pgp', body, crcLine?.slice(1));
    const at = Math.max(0, text.indexOf('-----BEGIN PGP'));
    return [{ kind: 'pgp', value: judged.value, encrypted: false, line: lineAt(text, at), index: at, body }];
  }

  // PuTTY の鍵（.ppk）：Private-Lines の後に秘密鍵の本体がある。Encryption が none 以外なら暗号化されている
  const putty = /^PuTTY-User-Key-File-\d+:/m.exec(text);
  if (putty && /^Private-Lines:\s*\d+/m.test(text)) {
    const enc = /^Encryption:\s*(\S+)/m.exec(text)?.[1] ?? 'none';
    const priv = /^Private-Lines:\s*\d+\r?\n([\s\S]*?)(?:\r?\n[A-Za-z-]+:|$)/m.exec(text)?.[1]?.replace(/\s/g, '') ?? '';
    const judged = classifyKeyBody('putty', priv);
    return [{ kind: 'putty', value: judged.value, encrypted: enc !== 'none', line: lineAt(text, putty.index), index: putty.index, body: priv }];
  }
  return [];
}

/** 結果に入れる形（本体・位置を落とす） */
function toMatch(c: PrivateKeyCandidate): PrivateKeyMatch {
  const m: PrivateKeyMatch = { kind: c.kind, value: c.value, encrypted: c.encrypted, line: c.line, index: c.index };
  if (c.unresolved) m.unresolved = true;
  return m;
}

/**
 * 文字列の中の秘密鍵をすべて探す。onBody：ダミー以外の鍵の本体を受け取る関数
 * （同じ鍵かどうかを、鍵を残さずに比べるため。鍵は結果には入れない）
 */
export function findPrivateKeys(text: string, onBody?: (body: string) => void): PrivateKeyMatch[] {
  return findPrivateKeyCandidates(text).map((c) => {
    if (c.value !== 'test-like') onBody?.(c.body);
    return toMatch(c);
  });
}

/** 最初に見つかった秘密鍵（1つだけ見ればよい場面・これまでの呼び出しとの互換） */
export function findPrivateKey(text: string, onBody?: (body: string) => void): PrivateKeyMatch | undefined {
  const first = findPrivateKeyCandidates(text)[0];
  if (!first) return undefined;
  if (first.value !== 'test-like') onBody?.(first.body);
  return toMatch(first);
}

/** 中身を確かめる鍵ファイルの候補（読むかどうかを決めるだけ。危険かどうかは中身で判定する） */
export function isKeyFileCandidate(name: string): boolean {
  return /\.(pem|key|p8|ppk|asc|txt)$/i.test(name) || /^id_(rsa|dsa|ecdsa|ed25519)$/.test(name);
}

// ───────────── 公開フォルダ ─────────────

/** Web からそのまま配信されるフォルダの名前（Next.js・Vite・Nuxt・Astro・Firebase Hosting の public、SvelteKit・Hugo・Gatsby などの static） */
export const PUBLIC_DIR_NAMES: ReadonlySet<string> = new Set(['public', 'static']);

/** データベースのバックアップ（ファイルの先頭の決まった形だけで判定する） */
export function dbBackupKind(head: Buffer, name: string, text: string | undefined): 'db-backup' | 'db-sql' | undefined {
  // SQLite のデータベースファイル（公式のファイル形式：先頭16バイトが "SQLite format 3\0"）
  if (head.subarray(0, 16).toString('latin1') === 'SQLite format 3\0') return 'db-backup';
  // pg_dump のカスタム形式（先頭が PGDMP）
  if (head.subarray(0, 5).toString('latin1') === 'PGDMP') return 'db-backup';
  if (!/\.sql$/i.test(name) || text === undefined) return undefined;
  // pg_dump・mysqldump・mariadb-dump の見出し、SQLite の .dump の書き出し
  if (/^-- (?:PostgreSQL database dump|MySQL dump|MariaDB dump)/m.test(text) || /^PRAGMA foreign_keys=OFF;\r?\nBEGIN TRANSACTION;/m.test(text)) return 'db-backup';
  // データ入りの SQL（テーブルの作成とデータの追加の両方がある）。見本のデータの可能性もあるので確認をすすめる
  if (/\bCREATE\s+TABLE\b/i.test(text) && /\bINSERT\s+INTO\b/i.test(text)) return 'db-sql';
  return undefined;
}

/** Google の OAuth クライアントの JSON（client_secret.json。"web" か "installed" の中に client_secret がある） */
export function isOAuthClientSecretJson(text: string): boolean {
  if (!text.includes('client_secret')) return false;
  try {
    const json: unknown = JSON.parse(text);
    if (!json || typeof json !== 'object') return false;
    for (const key of ['web', 'installed']) {
      const v = (json as Record<string, unknown>)[key];
      if (!v || typeof v !== 'object') continue;
      const secret = (v as Record<string, unknown>).client_secret;
      const id = (v as Record<string, unknown>).client_id;
      if (typeof secret === 'string' && typeof id === 'string' && secret.length >= 20 && !TEST_WORDS.test(secret) && /^[A-Za-z0-9_-]+$/.test(secret)) return true;
    }
  } catch {
    return false;
  }
  return false;
}

/** .env に、値の入った変数が1つ以上あるか（値そのものは見ない） */
export function envHasValues(text: string): boolean {
  return /^[ \t]*(?:export[ \t]+)?[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*[^\s#]/m.test(text);
}
