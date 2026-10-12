// .env 系ファイルの読み取り。
//
// 方針:
// ・外へ出す（画面に表示・保持する）のは「変数名」だけ。値は表示しない・保持しない。
// ・値を見るのは次の2つの判定のためだけで、判定が終わったら捨てる。
//   1. Supabase の URL（https://<ref>.supabase.co）からプロジェクトIDを取り出す（入力の手間を省くため）
//   2. アプリに埋め込まれる「公開用」の変数に、秘密の値らしきものが入っていないか

import { extractProjectRef } from '../cli/project-ref.js';

/** アプリ（ブラウザ・スマホアプリ）に埋め込まれ、誰でも見られる変数名の接頭辞 */
export const PUBLIC_ENV_PREFIXES = ['NEXT_PUBLIC_', 'EXPO_PUBLIC_', 'VITE_', 'REACT_APP_', 'PUBLIC_', 'NUXT_PUBLIC_', 'GATSBY_'];

export type SecretValueKind = 'supabase-secret-key' | 'supabase-service-role-jwt' | 'secret-api-key';

export interface EnvKeyInfo {
  name: string;
  /** 公開用の接頭辞が付いているか */
  isPublic: boolean;
  /** 名前が秘密情報らしいか（SECRET / SERVICE_ROLE / PRIVATE / PASSWORD など） */
  secretLikeName: boolean;
  /** 値が秘密のキーの形をしているか（値そのものは持たない） */
  secretLikeValue?: SecretValueKind;
}

export interface ParsedEnv {
  keys: EnvKeyInfo[];
  /** 値から取り出せた Supabase のプロジェクトID */
  supabaseRefs: string[];
}

const SECRET_NAME = /SECRET|SERVICE_ROLE|SERVICE_KEY|PRIVATE|PASSWORD|PASSWD/i;
const MAX_KEYS = 500;

function isPublicName(name: string): boolean {
  return PUBLIC_ENV_PREFIXES.some((p) => name.startsWith(p));
}

/** JWT の payload にある role を読む（署名は検証しない。分類のためだけ） */
function jwtRole(value: string): string | undefined {
  const parts = value.split('.');
  if (parts.length !== 3 || !parts[1]) return undefined;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as { role?: unknown };
    return typeof payload.role === 'string' ? payload.role : undefined;
  } catch {
    return undefined;
  }
}

/** 値が秘密のキーの形をしているかを判定する（値はこの関数の外へ出さない） */
export function classifySecretValue(value: string): SecretValueKind | undefined {
  const v = value.trim();
  if (v.startsWith('sb_secret_')) return 'supabase-secret-key';
  if (v.startsWith('eyJ') && jwtRole(v) === 'service_role') return 'supabase-service-role-jwt';
  // OpenAI（sk-...）、Stripe の秘密キー（sk_live_ / sk_test_）、Anthropic（sk-ant-...）など
  if (/^sk[-_](live_|test_|ant-|proj-)?[A-Za-z0-9_-]{16,}$/.test(v)) return 'secret-api-key';
  return undefined;
}

function unquote(raw: string): string {
  const v = raw.trim();
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) return v.slice(1, -1);
  // 行末コメントを取り除く（クォートなしの場合のみ）
  return v.replace(/\s+#.*$/, '');
}

export function parseEnv(text: string): ParsedEnv {
  const keys: EnvKeyInfo[] = [];
  const refs = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    if (keys.length >= MAX_KEYS) break;
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!m || !m[1]) continue;
    const name = m[1];
    const value = unquote(m[2] ?? '');
    const isPublic = isPublicName(name);
    const info: EnvKeyInfo = { name, isPublic, secretLikeName: SECRET_NAME.test(name) };
    if (isPublic) {
      const kind = classifySecretValue(value);
      if (kind) info.secretLikeValue = kind;
    }
    if (/SUPABASE.*URL|SUPABASE_PROJECT/i.test(name)) {
      const ref = extractProjectRef(value);
      if (ref) refs.add(ref);
    }
    keys.push(info);
  }
  return { keys, supabaseRefs: [...refs] };
}

/** .env ファイル名か（.env.example のような見本は値の判定の対象外にする） */
export function isEnvFileName(name: string): boolean {
  return name === '.env' || /^\.env\.[A-Za-z0-9_.-]+$/.test(name);
}

export function isEnvExampleName(name: string): boolean {
  return /\.(example|sample|template|dist)$/i.test(name);
}
