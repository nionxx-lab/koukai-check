// フォルダ選択から始まるアプリ画面の HTML。
// ・動的な値はすべて escapeHtml を通す
// ・外部リンクは、コード中に書いた公式ドキュメントのURL（許可リスト）だけ
// ・スクリプトは「処理中…」の表示だけ。通信（fetch）はしない（CSP の connect-src 'none'）

import { TECH_LABELS, type CheckItem, type CheckStatus } from '../checks/build.js';
import type { ScanResult } from '../detect/scan.js';
import { escapeHtml as e } from '../report/escape.js';
import { REPORT_STYLE } from '../report/html.js';
import { APP_DOC_HOSTS } from '../shared/url.js';
import { checkTokenInput } from '../supabase/token-check.js';
import type { TokenProblem } from './token-guide.js';

export function appContentSecurityPolicy(nonce: string, options: { forMeta?: boolean } = {}): string {
  const directives = [
    "default-src 'none'",
    `style-src 'nonce-${nonce}'`,
    `script-src 'nonce-${nonce}'`,
    "img-src 'none'",
    "font-src 'none'",
    "connect-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
  ];
  if (!options.forMeta) directives.push("frame-ancestors 'none'");
  return directives.join('; ');
}

/** アプリ画面のプライバシー表示（使っている技術に関係なく出すため、特定のサービス名は書かない） */
export const APP_PRIVACY_NOTICE_JA = [
  'このツールは、フォルダの中身・認証情報・診断結果を作者のサーバーへ送信しません。',
  'チェックと画面の表示は、このPC上で行われます。フォルダの中身を書き換えることはありません。',
];


export function docsHref(url: string): string | undefined {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' && APP_DOC_HOSTS.has(u.hostname) && !u.username && !u.port ? e(u.toString()) : undefined;
  } catch {
    return undefined;
  }
}

/** クエリに入れる値のエンコード（' ( ) などもエスケープして、属性・リンク判定で崩れないようにする） */
export function q(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*~]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

const APP_STYLE = `
.lead{font-size:17px;margin:0 0 20px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px 22px;margin:0 0 18px}
.btn{display:inline-block;font:inherit;font-size:16px;font-weight:700;padding:12px 22px;border-radius:10px;border:1px solid var(--accent);background:var(--accent);color:#fff;cursor:pointer;text-decoration:none}
.btn.secondary{background:transparent;color:var(--accent)}
.btn:focus-visible{outline:3px solid var(--fg);outline-offset:2px}
.row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
input[type=text],input[type=password]{font:inherit;width:100%;padding:10px 12px;border-radius:8px;border:1px solid var(--line);background:var(--bg);color:var(--fg);margin:6px 0 12px}
label{font-weight:600}
.chips{display:flex;gap:8px;flex-wrap:wrap;list-style:none;padding:0;margin:8px 0 0}
.chips li{background:var(--card);border:1px solid var(--line);border-radius:999px;padding:4px 14px;font-size:14px}
.chips li span{color:var(--muted);margin-left:6px}
.status{display:inline-block;font-size:13px;font-weight:700;border-radius:999px;padding:2px 10px}
.st-danger{background:var(--danger-bg);color:var(--danger)}.st-warn{background:var(--review-bg);color:var(--review)}
.st-action{background:var(--info-bg);color:var(--info)}.st-manual{background:var(--code);color:var(--muted)}.st-ok{background:var(--code);color:var(--accent)}
.card.sev-ok,.card.sev-manual{border-left-color:var(--line)}.card.sev-action{border-left-color:var(--info)}.card.sev-warn{border-left-color:var(--review)}
.card ul.points{margin:8px 0 0;padding-left:20px;font-size:14px}
.path{font-size:13px;color:var(--muted);word-break:break-all}
.msg{border-radius:10px;padding:12px 16px;margin:0 0 16px;background:var(--review-bg);border:1px solid var(--review)}
.busy{display:none;color:var(--muted);margin-left:8px}
.busy.on{display:inline}
ol.steps{padding-left:22px}ol.steps li{margin:4px 0}
.step h2{display:flex;align-items:center;gap:10px}
.step-no{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border-radius:50%;background:var(--accent);color:#fff;font-size:15px;flex:none}
ol.choose li{margin:8px 0}
.token-check{border-radius:8px;margin:0 0 12px;font-size:14px}
.token-check p{margin:0;padding:2px 0}
.token-check.st-danger,.token-check.st-warn,.token-check.st-ok{padding:8px 12px;font-weight:600}
.legacy-confirm{display:none}.legacy-confirm.on{display:block}
dialog.confirm{max-width:520px;width:calc(100% - 32px);border:1px solid var(--line);border-radius:12px;padding:20px 22px;background:var(--card);color:var(--fg)}
dialog.confirm::backdrop{background:rgba(0,0,0,.45)}
dialog.confirm h2{margin:0 0 12px;font-size:20px}
dialog.confirm .row{justify-content:flex-end;margin-top:18px}
.actions{margin-top:24px}
details.more{margin:8px 0 0;font-size:14px}details.more summary{cursor:pointer;color:var(--muted)}
details.more{color:var(--fg)}
.locs{margin:6px 0 0 18px;padding:0;color:inherit;background:transparent}
.loc{display:block;margin:2px 0;padding:0;color:inherit;background:transparent;opacity:1;visibility:visible;font:inherit;font-size:14px;line-height:1.6;white-space:normal;overflow-wrap:anywhere;text-indent:0}
`;

// フォーム送信時に「処理中…」を表示し、二重送信を防ぐだけのスクリプト
const APP_SCRIPT = `
document.addEventListener('submit', function (ev) {
  var form = ev.target;
  if (!(form instanceof HTMLFormElement)) return;
  if (form.getAttribute('data-busy') === '1') { ev.preventDefault(); return; }
  form.setAttribute('data-busy', '1');
  var busy = form.querySelector('.busy');
  if (busy) busy.classList.add('on');
});
`;

function layout(title: string, nonce: string, body: string, extraScript = ''): string {
  const n = e(nonce);
  return `<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${e(appContentSecurityPolicy(nonce, { forMeta: true }))}">
<meta name="referrer" content="same-origin">
<title>${e(title)}</title>
<style nonce="${n}">${REPORT_STYLE}${APP_STYLE}</style>
</head>
<body>
<main>
${body}
<footer>
  <p>${APP_PRIVACY_NOTICE_JA.map(e).join('<br>')}</p>
  <p>このツールは、確認の手助けをするものです。すべての問題を見つけられるわけではありません。</p>
</footer>
</main>
<script nonce="${n}">${APP_SCRIPT}${extraScript}</script>
</body>
</html>`;
}

function quitForm(base: string, csrf: string): string {
  return `<form method="post" action="${e(base)}quit"><input type="hidden" name="csrf" value="${e(csrf)}"><button class="btn secondary" type="submit">終了する</button></form>`;
}

// ───────────── ホーム（フォルダを選ぶ） ─────────────

export const HOME_MESSAGES: Record<string, string> = {
  cancelled: 'フォルダが選ばれませんでした。もう一度選んでください。',
  unavailable: 'このパソコンでは、フォルダを選ぶ画面を開けませんでした。下の欄にフォルダの場所を貼り付けてください。',
  'not-found': 'そのフォルダが見つかりませんでした。場所を確認してください。',
  'not-directory': 'フォルダではなくファイルが指定されました。アプリのフォルダを選んでください。',
  unreadable: 'そのフォルダを読み取れませんでした。',
  busy: 'フォルダを選ぶ画面がすでに開いています。タスクバーなどを確認してください。',
};

export function homePage(opts: { base: string; csrf: string; nonce: string; message?: string }): string {
  const msg = opts.message && HOME_MESSAGES[opts.message] ? `<p class="msg" role="alert">${e(HOME_MESSAGES[opts.message])}</p>` : '';
  const openManual = opts.message === 'unavailable' ? ' open' : '';
  return layout(
    '公開前チェック',
    opts.nonce,
    `<h1>公開前チェック</h1>
<p class="verdict">AIで作ったアプリを公開する前に、危ない設定がないか確認しましょう</p>
<p class="lead">チェックしたいアプリのフォルダを選ぶと、使っている技術を自動で調べて、必要なチェックだけを表示します。</p>
${msg}
<section class="panel">
  <form method="post" action="${e(opts.base)}pick">
    <input type="hidden" name="csrf" value="${e(opts.csrf)}">
    <button class="btn" type="submit">チェックするアプリのフォルダを選ぶ</button>
    <span class="busy" role="status">フォルダを選ぶ画面を開いています…（見当たらない場合はタスクバーを確認してください）</span>
  </form>
  <p class="hint">アプリを作ったときのフォルダ（package.json が入っているフォルダ）を選んでください。フォルダの中身は読むだけで、書き換えたり、外部に送ったりしません。</p>
  <details${openManual}>
    <summary>フォルダを選ぶ画面が開かない場合</summary>
    <form method="get" action="${e(opts.base)}scan">
      <label for="path">フォルダの場所を貼り付けてください</label>
      <input type="text" id="path" name="path" autocomplete="off" spellcheck="false" placeholder="例: C:\\Users\\あなた\\my-app">
      <button class="btn secondary" type="submit">このフォルダをチェックする</button>
    </form>
  </details>
</section>
<div class="row">${quitForm(opts.base, opts.csrf)}</div>`,
  );
}

// ───────────── チェック結果 ─────────────

const STATUS_LABEL: Record<CheckStatus, { label: string; order: number }> = {
  danger: { label: '🔴 公開前に確認・修正', order: 0 },
  warn: { label: '🟠 確認をおすすめ', order: 1 },
  action: { label: '🔵 追加でチェックできます', order: 2 },
  manual: { label: '📘 確認のヒント', order: 3 },
  ok: { label: '✅ 問題は見つかりませんでした', order: 4 },
};

function renderCheck(item: CheckItem, opts: { base: string; path: string }): string {
  const status = STATUS_LABEL[item.status];
  const points = item.points && item.points.length > 0 ? `<ul class="points">${item.points.slice(0, 30).map((p) => `<li><code>${e(p)}</code></li>`).join('')}</ul>` : '';
  // 折りたたみの中身は、1件ずつ <div> に「ファイル名:行番号」を本文の文字として直接入れる（箇条書き・疑似要素・属性は使わない）。
  // 空の行は出さず、中身がなければ折りたたみ自体を出さない
  const details = (item.details ?? [])
    .map((d) => {
      const lines = d.items.filter((x) => x.trim() !== '').slice(0, 50);
      if (lines.length === 0) return '';
      return `<details class="more"><summary>${e(d.summary)}</summary><div class="locs">${lines.map((x) => `<div class="loc">${e(x)}</div>`).join('')}</div></details>`;
    })
    .join('');
  const href = item.link ? docsHref(item.link.href) : undefined;
  const link = item.link && href ? `<p class="official"><a href="${href}" target="_blank" rel="noopener noreferrer">${e(item.link.label)}</a></p>` : '';
  const action = item.supabase
    ? `<p><a class="btn" href="${e(opts.base)}supabase?path=${q(opts.path)}">Supabase のチェックを始める</a></p>`
    : '';
  return `<article class="card sev-${item.status === 'danger' ? 'danger' : item.status}">
  <header><span class="status st-${item.status}">${e(status.label)}</span>
  <h3>${e(item.title)}</h3><p class="target">${e(TECH_LABELS[item.tech].name)}</p></header>
  <section><p>${e(item.body)}</p>${points}${details}</section>
  ${action}${link}
</article>`;
}

/** 技術を判定できなかったときの説明（直下の package.json の有無で変える） */
export function noTechMessage(scan: ScanResult): string {
  if (scan.rootPackageJson === 'found') {
    return 'package.json は見つかりましたが、このツールがチェックに対応している技術（Supabase・Firebase・Expo・React Native・Next.js・外部APIのキー・.env）は見つかりませんでした。';
  }
  if (scan.rootPackageJson === 'invalid') {
    return 'package.json は見つかりましたが、中身を読み取れませんでした（JSON の形式に誤りがあるか、ファイルが大きすぎる可能性があります）。';
  }
  return '使っている技術を判定できませんでした。アプリを作ったときの一番上のフォルダ（package.json が入っているフォルダ）を選び直してください。';
}

export function scanPage(opts: { base: string; csrf: string; nonce: string; scan: ScanResult; checks: CheckItem[] }): string {
  const { scan } = opts;
  const techs =
    scan.techs.length > 0
      ? `<ul class="chips">${scan.techs.map((t) => `<li>${e(TECH_LABELS[t.id].name)}<span>${e(TECH_LABELS[t.id].description)}</span></li>`).join('')}</ul>`
      : `<p class="msg">${e(noTechMessage(scan))}</p>`;
  const sorted = [...opts.checks].sort((a, b) => STATUS_LABEL[a.status].order - STATUS_LABEL[b.status].order);
  const cards = sorted.length > 0 ? sorted.map((c) => renderCheck(c, { base: opts.base, path: scan.root })).join('\n') : '<p class="empty">このフォルダでは、表示するチェックがありませんでした。</p>';
  // 件数の上限に達したときだけ知らせる（深さの上限はふつうのアプリでも当たるため、知らせない）。
  // 直下の package.json・.env・設定ファイルは上限に関係なく確認しているので、選び直しは求めない
  const truncated = scan.stats.truncated
    ? '<p class="msg">ファイルがとても多いため、奥のほうのフォルダは一部だけを調べました。選んだフォルダの直下にある package.json・.env・設定ファイルは、すべて確認済みです。</p>'
    : '';
  const detected = scan.techs
    .map((t) => `<li><b>${e(TECH_LABELS[t.id].name)}</b>: ${t.evidence.map((x) => `<code>${e(x)}</code>`).join('、')}</li>`)
    .join('');
  return layout(
    `公開前チェック：${scan.rootName}`,
    opts.nonce,
    `<p class="back"><a href="${e(opts.base)}">← 別のフォルダを選ぶ</a></p>
<h1>チェック結果</h1>
<p class="verdict">「${e(scan.rootName)}」をチェックしました</p>
<p class="path">${e(scan.root)}</p>
<h2>使われている技術</h2>
${techs}
${truncated}
<h2>このアプリに必要なチェック</h2>
<p class="disclaimer">フォルダ内の設定ファイルから分かる範囲の簡易チェックです。問題が表示されないことは、安全の保証ではありません。</p>
${cards}
<details class="tech"><summary>技術的な詳細を見る（判定の根拠）</summary><ul>${detected}</ul>
<p class="raw-label">調べたファイル・フォルダの数: ${scan.stats.entries}${scan.stats.unreadable ? `（読み取れなかったもの: ${scan.stats.unreadable}）` : ''}</p></details>
<div class="row actions">${quitForm(opts.base, opts.csrf)}</div>`,
  );
}

// ───────────── Supabase：トークン入力 ─────────────

/** Supabase のアクセストークンの作成ページ（既定のブラウザで開く） */
export const SUPABASE_TOKENS_URL = 'https://supabase.com/dashboard/account/tokens';

export interface TokenPageOptions {
  base: string;
  csrf: string;
  nonce: string;
  path: string;
  refs: string[];
  /** プロジェクトの入力に関するエラー */
  error?: string;
  ref?: string;
  /** 貼り付けたトークンの確認結果（サーバー側で見つけたもの） */
  tokenNotice?: { status: 'error' | 'warn'; messages: string[] };
  /** Supabase への問い合わせの失敗と、その直し方 */
  problem?: TokenProblem;
  /** 従来型（Legacy）のトークンを、確認のうえで使うかを聞く */
  askLegacy?: boolean;
  /** Supabase へ接続する確認の、一回限りの札（サーバーが画面ごとに発行する。トークンとは無関係） */
  connectTicket: string;
}

function openTokensButton(label: string): string {
  return `<p><a class="btn" href="${e(SUPABASE_TOKENS_URL)}" target="_blank" rel="noopener noreferrer">${e(label)}</a></p>`;
}

export function supabaseTokenPage(opts: TokenPageOptions): string {
  const refs = opts.refs;
  const known = refs.length === 1 && refs[0] ? refs[0] : undefined;
  let projectField: string;
  if (known) {
    projectField = `<p>チェックするプロジェクト: <code>${e(known)}</code>（アプリの設定ファイルから自動で見つけました）</p>
<input type="hidden" name="ref" value="${e(known)}">`;
  } else if (refs.length > 1) {
    projectField = `<p><label>チェックするプロジェクトを選んでください</label></p>${refs
      .map((r, i) => `<p><label><input type="radio" name="ref" value="${e(r)}"${(opts.ref ? opts.ref === r : i === 0) ? ' checked' : ''}> <code>${e(r)}</code></label></p>`)
      .join('')}`;
  } else {
    projectField = `<label for="ref">Supabase のプロジェクトのURL</label>
<p class="hint">アプリの設定ファイルから見つけられませんでした。Supabase のダッシュボードで対象のプロジェクトを開き、ブラウザのアドレス欄のURLを貼り付けてください。</p>
<input type="text" id="ref" name="ref" autocomplete="off" spellcheck="false" value="${e(opts.ref ?? '')}" placeholder="https://supabase.com/dashboard/project/...">`;
  }
  const projectLabel = known
    ? `<b>このアプリのプロジェクト（<code>${e(known)}</code>）だけ</b>を選ぶ`
    : refs.length > 1
      ? `<b>チェックしたいプロジェクト（${refs.map((r) => `<code>${e(r)}</code>`).join(' または ')}）だけ</b>を選ぶ`
      : '<b>このアプリのプロジェクトだけ</b>を選ぶ（「すべてのプロジェクト」は選ばない）';

  const error = opts.error ? `<div class="msg" role="alert">${e(opts.error).replace(/\n/g, '<br>')}</div>` : '';
  const problem = opts.problem
    ? `<div class="msg" role="alert"><p><b>${e(opts.problem.title)}</b></p>${
        opts.problem.fixes.length ? `<p>直し方：</p><ol class="steps">${opts.problem.fixes.map((f) => `<li>${e(f)}</li>`).join('')}</ol>` : ''
      }${opts.problem.recreate ? '<p class="hint">作り直す場合は、下の「ステップ2」の手順をもう一度行ってください。</p>' : ''}</div>`
    : '';
  const notice = opts.tokenNotice
    ? `<div class="token-check st-${opts.tokenNotice.status === 'error' ? 'danger' : 'warn'}" id="token-check" role="status" aria-live="polite">${opts.tokenNotice.messages.map((m) => `<p>${e(m)}</p>`).join('')}</div>`
    : '<div class="token-check" id="token-check" role="status" aria-live="polite"></div>';

  return layout(
    '公開前チェック：Supabase',
    opts.nonce,
    `<p class="back"><a href="${e(opts.base)}scan?path=${q(opts.path)}">← チェック結果に戻る</a></p>
<h1>Supabase のデータベース設定を確認する</h1>
<p class="lead">Supabase には、データベースの危ない設定を見つける公式の診断機能があります。その結果を、ここで分かりやすく表示します。4つのステップで進めます。</p>
${error}${problem}
<section class="panel step">
  <h2><span class="step-no">1</span>これから何をするか</h2>
  <p>Supabase に「このプロジェクトの診断結果を見せてください」とお願いするための、<b>専用の合言葉</b>を作ってもらいます。Supabase の画面では、この合言葉を「<b>アクセストークン</b>（Access Token）」と呼びます。</p>
  <ul class="points">
    <li>次のステップのとおりに作れば、この合言葉でできるのは<b>診断結果を読むことだけ</b>です。データの中身を読んだり、書き換えたりはできません。</li>
    <li>このツールは合言葉を<b>保存しません</b>。作者のサーバーにも送りません。Supabase への問い合わせにだけ使います。</li>
  </ul>
</section>
<section class="panel step">
  <h2><span class="step-no">2</span>Supabase で合言葉（アクセストークン）を作る</h2>
  ${openTokensButton('Supabase の作成ページをブラウザで開く')}
  <p class="hint">ブラウザで Supabase のページが開きます（ログインを求められたら、ふだんのアカウントでログインしてください）。新しく作るボタン（「Generate new token」など）を押し、次の<b>3つ</b>を選びます。</p>
  <ol class="steps choose">
    <li><b>対象のプロジェクト</b>：${projectLabel}</li>
    <li><b>権限</b>：一覧の「Project」の中にある <b>「Advisors」を「Read」</b>にする。<b>ほかの権限は付けない</b></li>
    <li><b>有効期限</b>：<b>できるだけ短く</b>する（例：1日や7日）。「無期限（Never）」は選ばない</li>
  </ol>
  <p class="hint">名前は何でもかまいません（例：koukai-check）。作ったあとに一度だけ表示される、<code>sbp_</code> で始まる文字列を、<b>画面を閉じる前にコピー</b>してください（あとから見ることはできません）。</p>
  <p class="hint">「Legacy」と表示される従来型や、権限を選ぶ画面が出ない作り方は、権限が強すぎるため<b>おすすめしません</b>。画面の表記が少し違う場合も、上の3つ（プロジェクト・Advisors の Read・短い期限）に合うものを選んでください。</p>
</section>
<section class="panel step">
  <h2><span class="step-no">3</span>貼り付けてチェックする</h2>
  <form method="post" action="${e(opts.base)}supabase/run" autocomplete="off" id="token-form">
    <input type="hidden" name="csrf" value="${e(opts.csrf)}">
    <input type="hidden" name="path" value="${e(opts.path)}">
    ${projectField}
    <label for="token">コピーした文字列（sbp_ で始まるもの）</label>
    <input type="password" id="token" name="token" autocomplete="off" spellcheck="false" placeholder="sbp_...">
    ${notice}
    <p class="legacy-confirm${opts.askLegacy ? ' on' : ''}" id="legacy-confirm"><label><input type="checkbox" name="allowLegacy" value="1"> おすすめしないことを理解したうえで、このまま従来型のトークンで続ける</label></p>
    <input type="hidden" name="connectConfirmed" value="" id="connect-confirmed">
    <input type="hidden" name="connectTicket" value="${e(opts.connectTicket)}">
    <p class="hint">貼り付けは Ctrl+V か、右クリック →「貼り付け」でできます。文字は ● で隠れて表示されます。</p>
    <button class="btn" type="submit">チェックする</button>
    <span class="busy" role="status">Supabase の設定を確認しています…</span>
  </form>
  <dialog class="confirm" id="connect-dialog" aria-labelledby="connect-title" aria-describedby="connect-body">
    <h2 id="connect-title">${e(CONNECT_DIALOG_TITLE)}</h2>
    <p id="connect-body">${CONNECT_DIALOG_BODY.map(e).join('<br>')}</p>
    <div class="row"><button class="btn secondary" type="button" id="connect-cancel">キャンセル</button><button class="btn" type="button" id="connect-ok">接続して診断する</button></div>
  </dialog>
</section>
<section class="panel step">
  <h2><span class="step-no">4</span>使い終わったら、合言葉を削除する</h2>
  <p>チェックが終わったら、作った合言葉は、作成したのと同じページで削除できます（もう一度チェックするときは、また作れます）。有効期限を短くしておけば、消し忘れても自動で使えなくなります。</p>
  ${openTokensButton('Supabase のページを開いて削除する').replace('class="btn"', 'class="btn secondary"')}
</section>`,
    TOKEN_SCRIPT,
  );
}

/** Supabase のオンライン診断で api.supabase.com へ接続する直前の確認（トークンの値は載せない） */
export const CONNECT_DIALOG_TITLE = 'Supabaseに接続します';
export const CONNECT_DIALOG_BODY = [
  'この診断では、Supabase公式API（api.supabase.com）へ接続して',
  'Security Advisorの結果を取得します。',
  '入力したアクセストークンは保存しません。',
];

/** 貼り付けた瞬間の確認（Supabase には問い合わせない）。checkTokenInput をそのまま埋め込む */
const TOKEN_SCRIPT = `
(function () {
  var checkTokenInput = ${checkTokenInput.toString()};
  var input = document.getElementById('token');
  var box = document.getElementById('token-check');
  var legacy = document.getElementById('legacy-confirm');
  var form = document.getElementById('token-form');
  if (!input || !box || !form) return;
  // 接続の確認。「接続して診断する」を押すまで送信しない（キャンセルなら何も送らない）
  var dialog = document.getElementById('connect-dialog');
  var confirmed = document.getElementById('connect-confirmed');
  var cancelButton = document.getElementById('connect-cancel');
  var okButton = document.getElementById('connect-ok');
  if (confirmed) confirmed.value = '';
  window.addEventListener('pageshow', function () { if (confirmed) confirmed.value = ''; });
  function closeDialog() { if (dialog && dialog.open) dialog.close(); }
  function openDialog() {
    if (!dialog) return;
    if (typeof dialog.showModal === 'function') dialog.showModal(); else dialog.setAttribute('open', '');
    if (cancelButton) cancelButton.focus();
  }
  if (cancelButton) cancelButton.addEventListener('click', function () {
    if (confirmed) confirmed.value = '';
    closeDialog();
    input.focus();
  });
  if (okButton) okButton.addEventListener('click', function () {
    if (confirmed) confirmed.value = '1';
    closeDialog();
    if (typeof form.requestSubmit === 'function') form.requestSubmit(); else form.submit();
  });
  function render(r) {
    box.textContent = '';
    box.className = 'token-check' + (r.status === 'error' ? ' st-danger' : r.status === 'warn' ? ' st-warn' : r.status === 'ok' ? ' st-ok' : '');
    var lines = r.status === 'empty' ? [] : r.fixed.concat(r.messages);
    lines.forEach(function (m) { var p = document.createElement('p'); p.textContent = m; box.appendChild(p); });
    if (legacy) legacy.classList.toggle('on', r.kind === 'legacy');
  }
  function update(fix) {
    var r = checkTokenInput(input.value);
    if (fix && r.fixed.length && r.token !== input.value) input.value = r.token;
    render(r);
    return r;
  }
  input.addEventListener('paste', function () { setTimeout(function () { update(true); }, 0); });
  input.addEventListener('input', function () { update(false); });
  form.addEventListener('submit', function (ev) {
    var r = update(true);
    if (r.status === 'empty' || r.status === 'error') {
      ev.preventDefault();
      ev.stopImmediatePropagation();
      if (r.status === 'empty') render({ status: 'error', kind: 'unknown', fixed: [], messages: r.messages });
      input.focus();
      return;
    }
    // 従来型で確認の印がないときは、サーバーが先に確認を求める（Supabase には接続しない）
    var allowLegacy = form.querySelector('input[name="allowLegacy"]');
    if (r.kind === 'legacy' && !(allowLegacy && allowLegacy.checked)) return;
    if (confirmed && confirmed.value === '1') return;
    ev.preventDefault();
    ev.stopImmediatePropagation();
    openDialog();
  }, true);
})();
`;

// ───────────── その他 ─────────────

export function messagePage(opts: { nonce: string; title: string; body: string; backHref?: string; backLabel?: string }): string {
  const back = opts.backHref ? `<p><a class="btn secondary" href="${e(opts.backHref)}">${e(opts.backLabel ?? '戻る')}</a></p>` : '';
  return layout(opts.title, opts.nonce, `<h1>${e(opts.title)}</h1><p class="lead">${e(opts.body)}</p>${back}`);
}
