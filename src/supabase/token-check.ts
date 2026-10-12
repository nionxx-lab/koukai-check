// 貼り付けられたアクセストークンの、その場での確認（Supabase には問い合わせない）。
//
// 画面（貼り付けた瞬間）とサーバー（「チェックする」を押したとき）の両方で、同じ関数を使う。
// 画面では、この関数のソースをそのまま <script> に埋め込むため、関数の外のものを参照しないこと（import も不可）。
// 結果のメッセージには、トークンの文字を一切含めない。
//
// 形式の根拠：Supabase docs "Personal Access Tokens" — 範囲を絞ったトークン（scoped）は `sbp_fc` で始まる。
// 従来型（Legacy）は `sbp_` で始まる。

export type TokenCheckStatus = 'empty' | 'error' | 'warn' | 'ok';
export type TokenCheckKind = 'scoped' | 'legacy' | 'unknown';

export interface TokenCheck {
  /** 空白などを取り除いたあとの値（これを Supabase に送る） */
  token: string;
  status: TokenCheckStatus;
  kind: TokenCheckKind;
  /** 利用者に見せる説明（トークンの文字は含まない） */
  messages: string[];
  /** 自動で直したこと */
  fixed: string[];
}

export function checkTokenInput(raw: string): TokenCheck {
  var fixed: string[] = [];
  var value = String(raw == null ? '' : raw);
  var normalized = value.normalize('NFKC');
  if (normalized !== value) fixed.push('全角の文字を半角にしました。');
  value = normalized;
  var noInvisible = value.replace(/[​-‍⁠﻿]/g, '');
  var noSpace = noInvisible.replace(/\s+/g, '');
  if (noSpace !== value) fixed.push('前後や途中の空白・改行を取り除きました。');
  value = noSpace;
  var unquoted = value.replace(/^["'`]+|["'`]+$/g, '');
  if (unquoted !== value) fixed.push('前後の引用符を取り除きました。');
  value = unquoted;
  if (/^bearer/i.test(value) && /sbp_/.test(value)) {
    value = value.replace(/^bearer:?/i, '');
    fixed.push('先頭の「Bearer」を取り除きました。');
  }
  var envMatch = /^SUPABASE_ACCESS_TOKEN=(.*)$/.exec(value);
  if (envMatch) {
    value = envMatch[1] || '';
    fixed.push('先頭の「SUPABASE_ACCESS_TOKEN=」を取り除きました。');
  }

  var result = function (status: TokenCheckStatus, kind: TokenCheckKind, messages: string[]): TokenCheck {
    return { token: value, status: status, kind: kind, messages: messages, fixed: fixed };
  };

  if (value === '') return result('empty', 'unknown', ['まだ貼り付けられていません。ステップ2で作った、sbp_ で始まる文字列を貼り付けてください。']);
  if (/(\.\.\.|…|\*{3,}|•|●)/.test(value)) {
    return result('error', 'unknown', [
      '省略された表示（… や ●）が含まれています。一部だけをコピーしたようです。',
      '作成した直後に一度だけ表示される、全文をコピーしてください。画面を閉じてしまった場合は、作り直してください。',
    ]);
  }
  if (/^eyJ/.test(value)) {
    return result('error', 'unknown', [
      'これは「anon key」や「service_role key」と呼ばれる、アプリ用の鍵です（eyJ で始まります）。ここで使うものとは別です。',
      'ステップ2の「アクセストークン」のページで作った、sbp_ で始まる文字列を貼り付けてください。',
      'service_role key は特に強い鍵です。人に見せたり、アプリの画面側のコードに入れたりしないでください。',
    ]);
  }
  if (/^sb_(publishable|secret)_/.test(value)) {
    return result('error', 'unknown', [
      'これはアプリ用の「API キー」（sb_publishable_ / sb_secret_ で始まる）です。ここで使うものとは別です。',
      'ステップ2の「アクセストークン」のページで作った、sbp_ で始まる文字列を貼り付けてください。',
    ]);
  }
  if (/^https?:/i.test(value)) {
    return result('error', 'unknown', ['URL が貼り付けられています。ここには、ステップ2で作った sbp_ で始まる文字列を貼り付けてください。']);
  }
  if (/^[a-z]{20}$/.test(value)) {
    return result('error', 'unknown', ['これはプロジェクトID（20文字の英小文字）のようです。ここには、ステップ2で作った sbp_ で始まる文字列を貼り付けてください。']);
  }
  if (!/^sbp_/.test(value)) {
    return result('error', 'unknown', ['Supabase のアクセストークン（sbp_ で始まる文字列）ではないようです。ステップ2で作った文字列を、最初から最後までコピーしてください。']);
  }
  if (/[^A-Za-z0-9_]/.test(value)) {
    return result('error', 'unknown', ['使えない文字が含まれています。コピーするときに余計な文字が入ったようです。もう一度コピーし直してください。']);
  }

  if (!/^sbp_fc/.test(value)) {
    var legacyMessages = [
      '権限を絞っていない、従来型（Legacy）のトークンのようです。あなたのアカウントのすべてのプロジェクトを操作できる強い権限があるため、おすすめしません。',
      'ステップ2の手順で、対象のプロジェクトと「Advisors：Read」だけを選んだトークンを作り直してください。',
    ];
    if (/^sbp_[0-9a-f]+$/.test(value) && value.length < 44) legacyMessages.push('また、途中で切れている可能性があります（短すぎます）。');
    return result('warn', 'legacy', legacyMessages);
  }
  if (value.length < 30) {
    return result('warn', 'scoped', ['範囲を絞ったトークンの形ですが、短すぎるようです。途中で切れていないか確認してください。']);
  }
  return result('ok', 'scoped', ['範囲を絞ったトークンの形です。「チェックする」を押してください。']);
}
