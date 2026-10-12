// トークンの見た目から種類を推定する（通信はしない）。
// 出典: Supabase docs "Personal Access Tokens" — scoped token は `sbp_fc` で始まる。

import type { TokenInfo, TokenKind } from '../types/diagnostic.js';

export function detectTokenKind(token: string): TokenKind {
  if (token.startsWith('sbp_fc')) return 'scoped';
  if (token.startsWith('sbp_')) return 'classic';
  return 'unknown';
}

export function describeToken(token: string): TokenInfo {
  const kind = detectTokenKind(token);
  if (kind === 'classic') {
    return {
      kind,
      isBroadAccess: true,
      noticeJa:
        'このトークンは Legacy（フルアクセス）のトークンです。あなたのアカウントのすべてのプロジェクトを操作できる強い権限を持っています。' +
        '可能であれば、対象プロジェクトの「Advisors: Read」だけを持つ Scoped トークンを使ってください。',
    };
  }
  if (kind === 'unknown') {
    return { kind, isBroadAccess: false, noticeJa: 'Supabaseのアクセストークンの形式（sbp_ で始まる）と異なります。' };
  }
  return { kind, isBroadAccess: false };
}
