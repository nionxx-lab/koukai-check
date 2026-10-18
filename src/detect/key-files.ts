// 秘密鍵・認証情報のファイルと、公開フォルダ（public/・static/ など）に入ると危険なファイルを、中身で見分ける。
//
// 方針：
// ・ファイル名や拡張子だけでは判定しない（.pem には公開してよい証明書もある）。中身の形が公式の形式に当てはまるものだけ
// ・本物らしさは、鍵の本体が正しい形（base64 を戻すと ASN.1 / openssh-key-v1 の形）かどうかで確かめる。形が崩れたダミーは数えない
// ・鍵の本体に「test」「fake」などの語が含まれるかでは判定しない（本物の鍵にも偶然含まれるため。src/detect/key-structure.ts）
// ・本物か判断できないものは、安全とは扱わず uncertain（確認をおすすめ）にする
// ・鍵・値は外へ出さない。返すのは種類・行番号・暗号化の有無だけ

import { classifyKeyBody, pemBodyLines, type KeyBodyValue } from './key-structure.js';

/** pem：PKCS#1/#8・EC などの PEM／openssh：OpenSSH 形式／pgp：PGP の秘密鍵／putty：PuTTY の鍵／service-account：Google・Firebase のサービスアカウント鍵 */
export type PrivateKeyKind = 'pem' | 'openssh' | 'pgp' | 'putty' | 'service-account';

export interface PrivateKeyMatch {
  kind: PrivateKeyKind;
  /** real-like：本物の鍵の構造／test-like：はっきりしたダミー（見本の文字・同じ値の繰り返し）／uncertain：本物か判断できない */
  value: KeyBodyValue;
  /** パスフレーズで暗号化されている */
  encrypted: boolean;
  line: number;
}

// OAuth クライアントの秘密（client_secret.json）の見本の値を見分けるための語（鍵の本体の判定には使わない）
const TEST_WORDS = /test|fake|dummy|mock|example|sample|placeholder|redacted|invalid|not[-_]?a[-_]?real|changeme|your[-_]|xxxx/i;

function lineAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

/** 文字列の中の秘密鍵を探す（JSON の "\n" のような書き方も読む）。最初に見つかった1つだけを返す */
/** onBody：本物の形の鍵の本体を受け取る関数（同じ鍵かどうかを、鍵を残さずに比べるため。鍵は結果には入れない） */
export function findPrivateKey(text: string, onBody?: (body: string) => void): PrivateKeyMatch | undefined {
  if (!/PRIVATE KEY|PuTTY-User-Key-File|service_account/.test(text)) return undefined;

  // サービスアカウント鍵（JSON）：type が service_account で、private_key に秘密鍵が入っている
  if (/"type"\s*:\s*"service_account"/.test(text)) {
    try {
      const json: unknown = JSON.parse(text);
      const o = json && typeof json === 'object' ? (json as Record<string, unknown>) : undefined;
      if (o?.type === 'service_account' && typeof o.private_key === 'string') {
        const inner = findPrivateKey(o.private_key, onBody);
        const at = text.indexOf('"private_key"');
        if (inner) return { ...inner, kind: 'service-account', line: lineAt(text, Math.max(0, at)) };
      }
    } catch {
      // JSON として読めなければ、下の PEM の判定に任せる
    }
  }

  const normalized = text.replace(/\\r\\n|\\n/g, '\n');
  const pem = /-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?)PRIVATE KEY-----([\s\S]*?)-----END \1PRIVATE KEY-----/.exec(normalized);
  if (pem) {
    const label = pem[1] ?? '';
    // コードの文字列リテラルとして連結して書いた鍵も、引用符の内側だけをつないで本体を取り出す
    const lines = pemBodyLines(normalized, pem.index, pem[2] ?? '');
    // 古い暗号化 PEM（Proc-Type: 4,ENCRYPTED）の見出し行は除く
    // Proc-Type の見出しは、カンマの有無を問わない
    const encrypted = label === 'ENCRYPTED ' || lines.some((l) => /^Proc-Type:4,?ENCRYPTED/i.test(l));
    const body = lines.filter((l) => !l.includes(':')).join('');
    const kind: PrivateKeyKind = label === 'OPENSSH ' ? 'openssh' : 'pem';
    // 古い形式の暗号化 PEM（Proc-Type）は、本体が暗号文なので ASN.1 の形にはならない
    const judged = classifyKeyBody(encrypted && label !== 'ENCRYPTED ' && label !== 'OPENSSH ' ? 'legacy-encrypted' : label, body);
    // 同じ鍵かどうかの比較（指紋）は、ダミー以外で行う（判断できない鍵も、履歴の確認の対象にする）
    if (judged.value !== 'test-like') onBody?.(body);
    return {
      kind,
      value: judged.value,
      encrypted: encrypted || judged.encrypted === true,
      line: lineAt(text, text.indexOf('-----BEGIN') >= 0 ? text.indexOf('-----BEGIN') : 0),
    };
  }

  const pgp = /-----BEGIN PGP PRIVATE KEY BLOCK-----([\s\S]*?)-----END PGP PRIVATE KEY BLOCK-----/.exec(normalized);
  if (pgp) {
    const lines = (pgp[1] ?? '').split('\n').map((l) => l.trim()).filter((l) => l && !l.includes(':'));
    // ASCII armor の最後の「=」で始まる行は、チェックサム（CRC-24）
    const crcLine = lines.length > 1 && /^=[A-Za-z0-9+/]{4}$/.test(lines[lines.length - 1] ?? '') ? lines.pop() : undefined;
    const body = lines.join('');
    const judged = classifyKeyBody('pgp', body, crcLine?.slice(1));
    if (judged.value !== 'test-like') onBody?.(body);
    return { kind: 'pgp', value: judged.value, encrypted: false, line: lineAt(text, text.indexOf('-----BEGIN PGP')) };
  }

  // PuTTY の鍵（.ppk）：Private-Lines の後に秘密鍵の本体がある。Encryption が none 以外なら暗号化されている
  const putty = /^PuTTY-User-Key-File-\d+:/m.exec(text);
  if (putty && /^Private-Lines:\s*\d+/m.test(text)) {
    const enc = /^Encryption:\s*(\S+)/m.exec(text)?.[1] ?? 'none';
    const priv = /^Private-Lines:\s*\d+\r?\n([\s\S]*?)(?:\r?\n[A-Za-z-]+:|$)/m.exec(text)?.[1]?.replace(/\s/g, '') ?? '';
    const judged = classifyKeyBody('putty', priv);
    if (judged.value !== 'test-like') onBody?.(priv);
    return { kind: 'putty', value: judged.value, encrypted: enc !== 'none', line: lineAt(text, putty.index) };
  }
  return undefined;
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
