// ターミナルに表示する文言。長文にしすぎない。

export const INTRO = [
  '公開前チェック',
  '',
  'AIで作ったSupabaseアプリを公開する前に、セキュリティ設定を確認します。',
  'このツールは、Supabaseの認証情報や診断結果を作者のサーバーへ送信しません。診断はこのPC上で行います。',
  '',
].join('\n');

export const PROJECT_PROMPT_HELP =
  '診断するプロジェクトを指定してください。\n' +
  'Supabaseのダッシュボードで対象プロジェクトを開いたときのURL（https://supabase.com/dashboard/project/...）か、プロジェクトID（20文字の英小文字）を貼り付けます。';

export const PROJECT_INVALID =
  'プロジェクトとして読み取れませんでした。ダッシュボードのURL、またはプロジェクトID（20文字の英小文字）を貼り付けてください。';

export const TOKEN_PROMPT_HELP =
  'Supabaseのアクセストークンを貼り付けてください（入力した文字は表示されません）。\n' +
  '日本語入力（IME）はオフにして、手で打たずに貼り付けてください。作り方が分からない場合は「?」と入力してください。';

export const TOKEN_GUIDE = [
  '',
  'トークンの作り方:',
  '  1. https://supabase.com/dashboard/account/tokens を開く',
  '  2. 新しいトークンを作成する',
  '  3. 対象は「診断したいプロジェクトだけ」、権限は「Advisors: Read」だけを選ぶ',
  '  4. 表示された sbp_ で始まる文字列をコピーして、ここに貼り付ける',
  'トークンはSupabaseへの問い合わせにだけ使い、保存しません。使い終わったら削除してかまいません。',
  '詳しく: https://supabase.com/docs/guides/platform/personal-access-tokens',
  '',
].join('\n');

export const LEGACY_TOKEN_WARNING =
  'このトークンは広い権限を持っています。可能であれば対象プロジェクトのAdvisors: Readだけを持つScoped Tokenの使用をおすすめします。';

export const CHECKING = 'Supabaseの設定を確認しています...';

export const HELP = [
  '使い方（開発者向け）: npx koukai-check supabase [オプション]',
  '',
  '  --project <URL または ID>   診断するプロジェクトを指定する',
  '  --no-open                   ブラウザを自動で開かない（URLだけ表示する）',
  '  --from-file <file.json>     保存したSecurity Advisorの結果を表示する（Supabaseへ接続しない）',
  '  --help                      この説明を表示する',
  '',
  'アクセストークンは、実行後の入力欄に貼り付けてください（入力した文字は表示されません）。',
  '環境変数 SUPABASE_ACCESS_TOKEN が設定されている場合は、それを使います。',
  'トークンをコマンドの引数に書く方法（--token など）には、履歴に残るため対応していません。',
].join('\n');

export const TOKEN_IN_ARGS = [
  'アクセストークンをコマンドに直接書く方法には対応していません。',
  'コマンドに書いたトークンは、シェルの履歴に残る可能性があります。',
  'そのトークンは Supabase のダッシュボード（https://supabase.com/dashboard/account/tokens）で削除し、作り直すことをおすすめします。',
  'トークンは、npx koukai-check を実行したあとの入力欄に貼り付けてください（入力した文字は表示されません）。',
].join('\n');

/** 対応する Node.js の最小メジャーバージョン */
export const MIN_NODE_MAJOR = 22;

export function nodeTooOldMessage(current: string): string {
  return `このツールには Node.js ${MIN_NODE_MAJOR} 以上が必要です（現在: ${current}）。https://nodejs.org から新しいバージョンをインストールしてください。`;
}
