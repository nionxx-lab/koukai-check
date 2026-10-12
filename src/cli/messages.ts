import type { SupabaseApiError } from '../supabase/errors.js';

// 初心者向けのエラーメッセージ。スタックトレースは出さない。
export function explainError(error: SupabaseApiError, context: 'projects' | 'advisors'): string {
  switch (error.kind) {
    case 'invalid_token':
      return [
        'アクセストークンが無効です。',
        '・コピーしたトークンが途中で切れていないか確認してください。',
        '・トークンを削除・失効していないか、Supabaseの Account > Access Tokens で確認してください。',
      ].join('\n');
    case 'forbidden':
      return context === 'projects'
        ? [
            'このトークンにはプロジェクト一覧を見る権限がありません。',
            'プロジェクトIDを直接入力すれば続行できます（Advisorsの読み取り権限だけで診断できます）。',
          ].join('\n')
        : [
            'このトークンには、このプロジェクトのSecurity Advisorを読む権限がありません。',
            '・トークン作成時に、対象プロジェクトの「Advisors」を Read にしてください。',
            '・プロジェクトを選び間違えていないか確認してください。',
            '・あなたのアカウント自体がそのプロジェクトにアクセスできるか確認してください。',
          ].join('\n');
    case 'not_found':
      return 'プロジェクトが見つかりません。プロジェクトID（20文字の英小文字）が正しいか確認してください。';
    case 'rate_limited':
      return 'Supabase APIの利用制限に達している可能性があります。数分待ってから、もう一度実行してください。';
    case 'server_error':
      return 'Supabase側でエラーが発生しました。時間をおいて再実行してください。（https://status.supabase.com で障害情報を確認できます）';
    case 'network':
      return [
        'Supabaseに接続できませんでした。インターネット接続やプロキシ設定を確認してください。',
        '会社や学校のネットワークでは、api.supabase.com への通信が制限されている場合があります。',
      ].join('\n');
    case 'unexpected_response':
      return [
        'Supabaseから想定外の形式の応答が返りました。',
        'Security Advisor API は Supabase で「実験的（experimental）」扱いのため、仕様が変わった可能性があります。',
        'ツールの更新を確認するか、GitHub Issues で報告してください。',
      ].join('\n');
  }
}
