// Supabase への問い合わせが失敗したとき、「何を直せばよいか」を初心者向けに説明する（アプリ画面用）。
// どのエラーでも、トークンの文字は表示しない。
//
// 範囲を絞ったトークンで、対象に含めていないプロジェクトを問い合わせた場合、Supabase は 403 と 404 の
// どちらを返すか公開されていないため、両方で「対象のプロジェクトの選び間違い」を案内する。

import { explainError } from '../cli/messages.js';
import type { SupabaseApiError } from '../supabase/errors.js';

export interface TokenProblem {
  title: string;
  /** 直し方（上から順に試してもらう） */
  fixes: string[];
  /** ステップ2（作り直し）へ戻るよう案内するか */
  recreate: boolean;
}

export function explainTokenProblem(error: SupabaseApiError, ref: string): TokenProblem {
  switch (error.kind) {
    case 'invalid_token':
      return {
        title: 'このアクセストークンは、Supabase に受け付けられませんでした（無効です）。',
        fixes: [
          'コピーが途中で切れていないか確認してください。作成した直後に表示される文字列を、最初から最後までコピーします。',
          '作成した画面を閉じてしまって全文が分からない場合は、ステップ2の手順でもう一度作ってください。',
          'そのトークンを削除した場合や、有効期限が切れた場合も、作り直してください。',
        ],
        recreate: true,
      };
    case 'forbidden':
      return {
        title: 'このアクセストークンでは、このプロジェクトの診断結果を見られませんでした（権限が足りません）。',
        fixes: [
          '作成画面の「権限」で、「Advisors」を「Read」にしたか確認してください。付け忘れた場合は、作り直します。',
          `作成画面の「対象のプロジェクト」で、このアプリのプロジェクト（${ref}）を選んだか確認してください。`,
          'あなたの Supabase のアカウントが、そのプロジェクトのメンバーになっているか確認してください（トークンは、アカウントにない権限を持てません）。',
        ],
        recreate: true,
      };
    case 'not_found':
      return {
        title: `プロジェクト（${ref}）が見つかりませんでした。`,
        fixes: [
          `作成画面の「対象のプロジェクト」で、このプロジェクト（${ref}）を選んだか確認してください。対象に含めていないプロジェクトは「見つからない」と返ることがあります。`,
          'プロジェクトのURLを貼り付けた場合は、チェックしたいアプリのプロジェクトのURLか確認してください。',
          'Supabase のダッシュボードで、プロジェクトが一時停止・削除されていないか確認してください。',
        ],
        recreate: true,
      };
    default:
      return { title: explainError(error, 'advisors').split('\n')[0] ?? '', fixes: explainError(error, 'advisors').split('\n').slice(1), recreate: false };
  }
}
