// 秘密鍵の本体（base64）が、本物の鍵の構造かどうかを確かめる（src/detect/key-files.ts・secret-names.ts から使う）。

/** real-like：鍵の構造が正しく、中身がランダム／test-like：はっきりしたダミー（見本の文字・短すぎる・同じ値の繰り返し）／uncertain：本物か判断できない */
export type KeyBodyValue = 'real-like' | 'test-like' | 'uncertain';

// 鍵の本体（base64）に「test」「fake」などの語が含まれるかでは判定しない。
// 本物の鍵の本体はランダムな文字列なので、これらの語の並びが偶然含まれることがある（見逃しの原因になる）。
// 代わりに、base64 を戻した中身が鍵の構造（ASN.1・openssh-key-v1・PGP のパケット）になっているか、
// 中身がランダムかで判定する。見本の文字（「...」「<...>」「YOUR_KEY」など）は base64 として読めないので、ダミーとして分かる。

const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

/** 中身がランダムか（同じ値の繰り返し・ゼロ埋めのダミーを見分ける） */
function looksRandomBytes(bytes: Uint8Array): boolean {
  if (bytes.length < 16) return false;
  const seen = new Set<number>();
  for (const b of bytes) seen.add(b);
  return seen.size >= Math.min(48, Math.floor(bytes.length / 4));
}

/** DER の長さ（短い形・長い形）を読む。読めなければ undefined */
function readDer(bytes: Uint8Array, at: number): { tag: number; start: number; end: number } | undefined {
  if (at + 2 > bytes.length) return undefined;
  const tag = bytes[at] ?? 0;
  let len = bytes[at + 1] ?? 0;
  let start = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || start + n > bytes.length) return undefined;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + (bytes[start + i] ?? 0);
    start += n;
  }
  const end = start + len;
  return end <= bytes.length ? { tag, start, end } : undefined;
}

/** PKCS#1・PKCS#8（暗号化を含む）・SEC1（EC）・DSA：外側の SEQUENCE がちょうど全体で、中の要素を最後まで読めること */
function derKeyOk(bytes: Uint8Array): boolean {
  const outer = readDer(bytes, 0);
  if (!outer || outer.tag !== 0x30 || outer.end !== bytes.length) return false;
  let at = outer.start;
  let children = 0;
  while (at < outer.end) {
    const child = readDer(bytes, at);
    if (!child || child.end > outer.end) return false;
    at = child.end;
    children++;
  }
  return children >= 2 && at === outer.end;
}

/** OpenSSH の秘密鍵（openssh-key-v1）：見出しの後に、暗号の名前・鍵の導出の名前・鍵の数が正しい形で並んでいること */
function opensshInfo(bytes: Uint8Array): { ok: boolean; encrypted: boolean } {
  const magic = 'openssh-key-v1\0';
  if (Buffer.from(bytes.subarray(0, magic.length)).toString('latin1') !== magic) return { ok: false, encrypted: false };
  let at = magic.length;
  const view = Buffer.from(bytes);
  const str = (): string | undefined => {
    if (at + 4 > view.length) return undefined;
    const len = view.readUInt32BE(at);
    if (len > 1024 || at + 4 + len > view.length) return undefined;
    const s = view.subarray(at + 4, at + 4 + len).toString('latin1');
    at += 4 + len;
    return s;
  };
  const cipher = str();
  const kdf = str();
  const options = str();
  if (cipher === undefined || kdf === undefined || options === undefined) return { ok: false, encrypted: false };
  if (!/^[a-z0-9@.-]{1,64}$/.test(cipher) || !/^[a-z0-9@.-]{1,64}$/.test(kdf)) return { ok: false, encrypted: false };
  if (at + 4 > view.length) return { ok: false, encrypted: false };
  const keys = view.readUInt32BE(at);
  at += 4;
  const rest = bytes.subarray(at);
  return { ok: keys >= 1 && keys <= 16 && rest.length >= 32 && looksRandomBytes(rest), encrypted: cipher !== 'none' };
}

/** PGP の秘密鍵：最初のパケットが秘密鍵（タグ 5）であること */
function pgpSecretKeyPacket(bytes: Uint8Array): boolean {
  const first = bytes[0] ?? 0;
  if (!(first & 0x80)) return false;
  const tag = first & 0x40 ? first & 0x3f : (first >> 2) & 0x0f;
  return tag === 5;
}

/** PGP の ASCII armor の CRC-24 */
function crc24(bytes: Uint8Array): number {
  let crc = 0xb704ce;
  for (const b of bytes) {
    crc ^= b << 16;
    for (let i = 0; i < 8; i++) {
      crc <<= 1;
      if (crc & 0x1000000) crc ^= 0x1864cfb;
    }
  }
  return crc & 0xffffff;
}

/**
 * 鍵の本体を判定する。kind は PEM の見出し（'OPENSSH ' など）・'pgp'・'putty'・'legacy-encrypted'（Proc-Type の暗号化 PEM）。
 * 判定できないものは安全とは扱わず uncertain を返す（画面では「確認をおすすめ」）。
 */
export function classifyKeyBody(kind: string, body: string, crc?: string): { value: KeyBodyValue; encrypted?: boolean } {
  // base64 として読めない（「...」「<...>」「YOUR_KEY」などの見本の書き方）・短すぎる → ダミー
  if (!BASE64.test(body) || body.length < 40) return { value: 'test-like' };
  const bytes = new Uint8Array(Buffer.from(body, 'base64'));
  // 同じ値の繰り返し・ゼロ埋め（AAAA… など）→ ダミー
  if (!looksRandomBytes(bytes)) return { value: 'test-like' };
  if (kind === 'OPENSSH ') {
    const info = opensshInfo(bytes);
    return info.ok ? { value: 'real-like', encrypted: info.encrypted } : { value: 'uncertain' };
  }
  if (kind === 'pgp') {
    if (crc !== undefined) {
      const expected = Buffer.from(crc, 'base64');
      const ok = expected.length === 3 && expected.readUIntBE(0, 3) === crc24(bytes);
      if (!ok) return { value: 'uncertain' };
    }
    return { value: pgpSecretKeyPacket(bytes) && bytes.length >= 100 ? 'real-like' : 'uncertain' };
  }
  if (kind === 'putty' || kind === 'legacy-encrypted') {
    // PuTTY の秘密の部分・古い形式の暗号化 PEM の本体は、決まった構造を外から確かめられない（ランダムなら本物らしいとする）
    return { value: bytes.length >= 32 ? 'real-like' : 'uncertain' };
  }
  return { value: derKeyOk(bytes) ? 'real-like' : 'uncertain' };
}

/**
 * PEM の1行から、鍵の本体（base64）だけを取り出す。
 * コードの中で文字列を連結して書いた鍵（"…" + "…"）の、引用符・連結の + ・カンマ・空白を取り除く。
 * base64 の文字としての + は残す（取り除くと本物の鍵の本体が壊れる）。連結の + は、引用符の隣か、その行に + だけがある場合
 */
export function cleanPemLine(line: string): string {
  const s = line
    .replace(/["'`]\s*\+\s*$/, '') // "…" + （行末の連結）
    .replace(/^\s*\+\s*["'`]/, '') // + "…" （行頭の連結）
    .replace(/["'`,\\\s]/g, '');
  return s === '+' ? '' : s;
}
