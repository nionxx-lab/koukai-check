// 診断レポートの HTML を生成する。
//
// 安全対策:
// ・プロジェクト由来の文字列（テーブル名、Advisorの文字列など）はすべて escapeHtml を通す。
// ・診断データを <script> 内へ埋め込まない。AI修正指示は readonly の <textarea> に入れ、スクリプトは値を読むだけ。
// ・インラインの style / script は nonce で許可し、それ以外は CSP で禁止する。
// ・外部CDN・外部フォント・画像・解析ツールは使わない（通信先がないことを CSP の connect-src 'none' でも保証）。
// ・アクセストークンはこの関数に渡さない（DiagnosticReport はトークンの値を持たない）。

import { sanitizeName } from '../diagnostics/classify.js';
import { resourceTypeLabel } from '../explanations/template.js';
import type { Diagnostic, DiagnosticReport, DiagnosticSeverity, ShouldFixBeforeRelease } from '../types/diagnostic.js';
import { escapeHtml as e, escapeWithInlineCode as ec, safeHref } from './escape.js';
import { describeObservedAt } from './time.js';

export interface RenderOptions {
  /** CSP 用の nonce（リクエストごとではなく、サーバー起動ごとに生成すればよい） */
  nonce: string;
  /** Supabase から結果を取得した時刻 */
  fetchedAt: Date;
  /** 表示用のプロジェクトID（任意） */
  projectRef?: string;
  /** フォルダ選択から開いた場合の「戻る」リンク（同じサーバー内の相対パスのみ） */
  backLink?: { href: string; label: string };
  /** フッターの終了方法の説明を差し替える（アプリ画面から開いた場合） */
  footerNote?: string;
}

export const PRIVACY_NOTICE_JA = [
  'このツールは、Supabaseの認証情報・テーブル情報・診断結果を作者のサーバーへ送信しません。',
  '診断処理とレポート表示は、このPC上で行われます。',
];

export const INCOMPLETE_NOTICE_JA = [
  'この診断結果には確認できなかった項目があります。',
  '「問題なし」とは判断しないでください。',
];

/**
 * Content Security Policy。frame-ancestors は <meta> では無効なため、HTTPヘッダーにだけ付ける。
 */
export function contentSecurityPolicy(nonce: string, options: { forMeta?: boolean } = {}): string {
  const directives = [
    "default-src 'none'",
    `style-src 'nonce-${nonce}'`,
    `script-src 'nonce-${nonce}'`,
    "img-src 'none'",
    "font-src 'none'",
    "connect-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
  ];
  if (!options.forMeta) directives.push("frame-ancestors 'none'");
  return directives.join('; ');
}

const SEVERITY: Record<DiagnosticSeverity, { icon: string; label: string; section: string }> = {
  danger: { icon: '🔴', label: '危険', section: '危険：公開前に確認・修正してください' },
  review: { icon: '🟠', label: '要確認', section: '要確認：意図した設定か確認してください' },
  info: { icon: '🔵', label: '参考', section: '参考：知っておくと安心な項目' },
};

const SHOULD_FIX: Record<ShouldFixBeforeRelease, string> = {
  yes: '公開前に修正することをおすすめします。',
  review: '公開前に、意図した設定かどうかを確認することをおすすめします。',
  no: 'すぐに公開を止める必要はありません。時間のあるときに見直すと安心です。',
};

/** 「技術的な詳細」に表示する文字列の上限（極端な応答でHTMLが巨大化しないように） */
export const MAX_DETAIL_TEXT = 2000;
export const MAX_RAW_JSON = 20_000;

function clip(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}…（長いため省略しました）` : text;
}

function targetLabel(d: Diagnostic): string {
  const name = d.resourceName ? sanitizeName(d.resourceName) : undefined;
  const schema = d.resourceSchema ? sanitizeName(d.resourceSchema) : undefined;
  const qualified = name ? (schema ? `${schema}.${name}` : name) : undefined;
  if (!qualified) return d.resourceType === 'auth' ? '認証（Auth）の設定' : 'プロジェクト全体の設定';
  const label = resourceTypeLabel(d.resourceType);
  return `<code>${e(qualified)}</code>${label ? `（${e(label)}）` : ''}`;
}

function anchorId(index: number): string {
  return `d${index + 1}`;
}

function renderRelated(d: Diagnostic, report: DiagnosticReport, idToAnchor: Map<string, string>): string {
  const group = report.groups.find((g) => g.resourceKey === d.resourceKey);
  if (!group || group.diagnosticIds.length < 2 || d.resourceKey.startsWith('advisor:')) return '';
  const others = group.diagnosticIds
    .filter((id) => id !== d.id)
    .map((id) => {
      const other = report.diagnostics.find((x) => x.id === id);
      const anchor = idToAnchor.get(id);
      return other && anchor ? `<li><a href="#${anchor}">${SEVERITY[other.severity].icon} ${ec(other.titleJa)}</a></li>` : '';
    })
    .join('');
  return others ? `<div class="related"><p>同じ対象への別の指摘:</p><ul>${others}</ul></div>` : '';
}

function renderTechnical(d: Diagnostic): string {
  const rows: [string, string | undefined][] = [
    ['Supabaseの診断項目', clip(d.advisorName, 200)],
    ['公式の重要度', d.officialSeverity ?? '不明'],
    ['公式のタイトル', clip(d.officialTitle, 500)],
    ['公式の説明', clip(d.officialDetail, MAX_DETAIL_TEXT)],
    ['このツールの分類理由', d.severityReason],
    ['診断時刻（UTC）', d.observedAt ? clip(d.observedAt, 100) : undefined],
  ];
  const table = rows
    .filter(([, v]) => v)
    .map(([k, v]) => `<tr><th>${e(k)}</th><td>${e(v)}</td></tr>`)
    .join('');
  let raw = '';
  try {
    raw = clip(JSON.stringify(d.originalAdvisorData, null, 2) ?? '', MAX_RAW_JSON);
  } catch {
    raw = '';
  }
  return `<details class="tech"><summary>技術的な詳細を見る</summary>
<table>${table}</table>
${raw ? `<p class="raw-label">Supabaseから返された元データ</p><pre>${e(raw)}</pre>` : ''}
</details>`;
}

function renderCard(d: Diagnostic, index: number, report: DiagnosticReport, idToAnchor: Map<string, string>): string {
  const sev = SEVERITY[d.severity];
  const href = safeHref(d.helpUrl);
  const promptId = `prompt-${index + 1}`;
  const unknownNote =
    d.definitionStatus === 'unknown'
      ? '<p class="note">このツールがまだ日本語の説明に対応していない項目です。問題がないという意味ではありません。</p>'
      : '';
  return `<article class="card sev-${d.severity}" id="${anchorId(index)}">
  <header>
    <span class="badge">${sev.icon} ${sev.label}</span>
    <h3>${ec(d.titleJa)}</h3>
    <p class="target">対象: ${targetLabel(d)}</p>
  </header>
  ${unknownNote}
  <section><h4>なぜ問題なのか</h4><p>${ec(d.explanationJa)}</p></section>
  <section><h4>公開前にどうすべきか</h4><p class="should-fix">${e(SHOULD_FIX[d.shouldFixBeforeRelease])}</p></section>
  <section><h4>修正方針</h4><p>${ec(d.remediationJa)}</p></section>
  <section class="ai">
    <h4>AIに修正を頼む</h4>
    <p class="hint">Claude Code や Codex に、次の指示をそのまま貼り付けて使えます。</p>
    <button type="button" class="copy" data-target="${promptId}">AIに修正を頼む指示をコピー</button>
    <span class="copied" role="status" aria-live="polite"></span>
    <details class="prompt-preview"><summary>指示の内容を見る</summary>
      <textarea id="${promptId}" readonly rows="14">${e(d.aiFixPrompt)}</textarea>
    </details>
  </section>
  ${href ? `<p class="official"><a href="${href}" target="_blank" rel="noopener noreferrer">Supabase公式の解説を開く（英語）</a></p>` : ''}
  ${renderRelated(d, report, idToAnchor)}
  ${renderTechnical(d)}
</article>`;
}

function renderNotices(report: DiagnosticReport): string {
  const parts: string[] = [];
  const hasUnknown = report.unknownAdvisorNames.length > 0;
  if (report.incomplete || hasUnknown) {
    const reasons: string[] = [];
    const tooMany = report.parseIssues.some((i) => i.reason === 'too_many');
    const unreadable = report.parseIssues.filter((i) => i.reason !== 'too_many').length;
    if (unreadable > 0) reasons.push(`Supabaseから返された結果のうち ${unreadable} 件を読み取れませんでした。`);
    if (tooMany) reasons.push('指摘の件数が非常に多いため、一部だけを表示しています。');
    const failed = report.diagnostics.filter((d) => d.affectsCompleteness);
    if (failed.length > 0) reasons.push('Supabase側で実行できなかった診断があります。');
    if (hasUnknown) {
      const names = report.unknownAdvisorNames.slice(0, 20).map((n) => `<code>${e(sanitizeName(n))}</code>`).join('、');
      const more = report.unknownAdvisorNames.length > 20 ? ` ほか${report.unknownAdvisorNames.length - 20}件` : '';
      reasons.push(`このツールが未対応の診断項目が含まれています（${names}${more}）。下の一覧に「参考」として表示しています。`);
    }
    parts.push(`<div class="notice warn" role="alert">
  <p class="strong">${INCOMPLETE_NOTICE_JA.map(e).join('<br>')}</p>
  ${reasons.length > 0 ? `<ul>${reasons.map((r) => `<li>${r}</li>`).join('')}</ul>` : ''}
</div>`);
  }
  if (report.token?.isBroadAccess) {
    parts.push(`<div class="notice token" role="note">
  <p class="strong">このトークンは広い権限を持っています。</p>
  <p>可能であれば、対象プロジェクトの「Advisors: Read」だけを持つ Scoped Token の使用をおすすめします。使い終わったトークンは、Supabaseのダッシュボードで削除できます。</p>
</div>`);
  }
  return parts.join('\n');
}

function renderSections(report: DiagnosticReport): string {
  if (report.diagnostics.length === 0) {
    return '<p class="empty">Supabase Security Advisor から、表示する指摘は返されませんでした。</p>';
  }
  const idToAnchor = new Map(report.diagnostics.map((d, i) => [d.id, anchorId(i)]));
  const order: DiagnosticSeverity[] = ['danger', 'review', 'info'];
  return order
    .map((sev) => {
      const cards = report.diagnostics
        .map((d, i) => (d.severity === sev ? renderCard(d, i, report, idToAnchor) : ''))
        .filter(Boolean);
      if (cards.length === 0) return '';
      return `<section class="group"><h2>${SEVERITY[sev].icon} ${e(SEVERITY[sev].section)}（${cards.length}件）</h2>\n${cards.join('\n')}</section>`;
    })
    .join('\n');
}

export const REPORT_STYLE = `
:root{--bg:#f6f7f9;--fg:#1d2127;--muted:#5b6470;--card:#fff;--line:#dfe3e8;--danger:#c62828;--danger-bg:#fdecec;--review:#b45309;--review-bg:#fff4e0;--info:#1d5fbf;--info-bg:#e8f0fc;--code:#eef0f3;--accent:#0f766e}
@media (prefers-color-scheme:dark){:root{--bg:#14171b;--fg:#e8eaed;--muted:#a3abb5;--card:#1d2127;--line:#323840;--danger:#ff8a80;--danger-bg:#3a1f1f;--review:#ffb74d;--review-bg:#3a2d17;--info:#8ab4f8;--info-bg:#1c2a40;--code:#2a2f36;--accent:#5eead4}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:system-ui,-apple-system,"Segoe UI","Hiragino Sans","Noto Sans JP","Yu Gothic UI",Meiryo,sans-serif;line-height:1.75;font-size:16px}
main{max-width:860px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:15px;color:var(--muted);font-weight:600;margin:0 0 8px;letter-spacing:.04em}
.verdict{font-size:26px;line-height:1.4;margin:0 0 20px}
.verdict.v-danger{color:var(--danger)}.verdict.v-review{color:var(--review)}
.summary{display:flex;gap:12px;flex-wrap:wrap;margin:0 0 12px;padding:0;list-style:none}
.summary li{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 16px;min-width:120px;font-size:17px}
.summary b{font-size:22px;margin-left:6px}
.meta{color:var(--muted);font-size:14px;margin:4px 0}
.disclaimer{font-size:14px;color:var(--muted);border-left:3px solid var(--line);padding-left:12px;margin:16px 0}
.notice{border-radius:10px;padding:14px 18px;margin:16px 0;border:1px solid}
.notice.warn{background:var(--review-bg);border-color:var(--review)}
.notice.token{background:var(--info-bg);border-color:var(--info)}
.notice ul{margin:8px 0 0;padding-left:20px}
.strong{font-weight:700;margin:0}
.group h2{font-size:19px;margin:40px 0 12px}
.card{background:var(--card);border:1px solid var(--line);border-left:6px solid var(--line);border-radius:12px;padding:20px 22px;margin:0 0 18px}
.card.sev-danger{border-left-color:var(--danger)}.card.sev-review{border-left-color:var(--review)}.card.sev-info{border-left-color:var(--info)}
.badge{display:inline-block;font-size:13px;font-weight:700;border-radius:999px;padding:2px 10px}
.sev-danger .badge{background:var(--danger-bg);color:var(--danger)}.sev-review .badge{background:var(--review-bg);color:var(--review)}.sev-info .badge{background:var(--info-bg);color:var(--info)}
.card h3{font-size:18px;line-height:1.5;margin:8px 0 4px}
.target{color:var(--muted);font-size:14px;margin:0}
.card h4{font-size:14px;margin:16px 0 2px;color:var(--muted)}
.card section p{margin:0}
.should-fix{font-weight:600}
code{background:var(--code);border-radius:4px;padding:1px 5px;font-size:.92em;word-break:break-all}
.ai{background:var(--bg);border-radius:10px;padding:4px 14px 12px;margin-top:16px}
.hint{font-size:14px;color:var(--muted)}
button.copy{font:inherit;font-size:15px;font-weight:600;margin-top:8px;padding:8px 16px;border-radius:8px;border:1px solid var(--accent);background:var(--accent);color:#fff;cursor:pointer}
button.copy:focus-visible{outline:3px solid var(--fg);outline-offset:2px}
.copied{margin-left:10px;font-size:14px;color:var(--accent);font-weight:600}
textarea{width:100%;margin-top:8px;font:13px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:10px}
details summary{cursor:pointer;color:var(--muted);font-size:14px;margin-top:10px}
.official{margin:14px 0 0;font-size:14px}
a{color:var(--info)}
.related{font-size:14px;margin-top:12px}.related p{margin:0;color:var(--muted)}.related ul{margin:2px 0 0;padding-left:20px}
.note{font-size:14px;background:var(--review-bg);border-radius:8px;padding:8px 12px;margin:10px 0 0}
.tech table{border-collapse:collapse;width:100%;font-size:13px;margin-top:8px}
.tech th,.tech td{border-top:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
.tech th{width:30%;color:var(--muted);font-weight:600}
.tech pre{background:var(--code);border-radius:8px;padding:10px;overflow:auto;font-size:12px;max-height:320px}
.raw-label{font-size:13px;color:var(--muted);margin:10px 0 0}
.empty{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px}
footer{margin-top:48px;padding-top:16px;border-top:1px solid var(--line);font-size:14px;color:var(--muted)}
@media (max-width:560px){.verdict{font-size:22px}.card{padding:16px}.summary li{min-width:0;flex:1}}
`;

// クリップボードへのコピーだけを行う。診断データはスクリプトに含めず、textarea の値を読む。
const SCRIPT = `
document.addEventListener('click', async function (ev) {
  var btn = ev.target instanceof Element ? ev.target.closest('button.copy') : null;
  if (!btn) return;
  var area = document.getElementById(btn.getAttribute('data-target') || '');
  var status = btn.parentElement ? btn.parentElement.querySelector('.copied') : null;
  if (!area) return;
  var ok = false;
  try {
    await navigator.clipboard.writeText(area.value);
    ok = true;
  } catch (_) {
    try {
      var details = area.closest('details');
      var wasOpen = details ? details.open : true;
      if (details) details.open = true;
      area.focus();
      area.select();
      ok = document.execCommand('copy');
      if (details) details.open = wasOpen;
    } catch (_) { ok = false; }
  }
  if (status) {
    status.textContent = ok ? 'コピーしました' : 'コピーできませんでした。「指示の内容を見る」から選択してコピーしてください。';
    setTimeout(function () { status.textContent = ''; }, 3000);
  }
});
`;

export function renderReportHtml(report: DiagnosticReport, options: RenderOptions): string {
  const nonce = e(options.nonce);
  const verdictClass = report.overall === 'fix-before-release' ? 'v-danger' : report.overall === 'review-before-release' ? 'v-review' : '';
  return `<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${e(contentSecurityPolicy(options.nonce, { forMeta: true }))}">
<meta name="referrer" content="no-referrer">
<title>公開前チェック結果</title>
<style nonce="${nonce}">${REPORT_STYLE}</style>
</head>
<body>
<main>
  ${options.backLink && /^\.?\/?[A-Za-z0-9/_?=&.%-]*$/.test(options.backLink.href) ? `<p class="back"><a href="${e(options.backLink.href)}">← ${e(options.backLink.label)}</a></p>` : ''}
  <h1>公開前チェック結果${options.projectRef ? ` ・ <code>${e(options.projectRef)}</code>` : ''}</h1>
  <p class="verdict ${verdictClass}">${e(report.headlineJa)}</p>
  <ul class="summary" aria-label="件数">
    <li>🔴 危険<b>${report.counts.danger}</b>件</li>
    <li>🟠 要確認<b>${report.counts.review}</b>件</li>
    <li>🔵 参考<b>${report.counts.info}</b>件</li>
  </ul>
  <p class="meta">診断結果の取得時刻: ${e(describeObservedAt(report.observedAt, options.fetchedAt))}</p>
  <p class="disclaimer">${e(report.disclaimerJa)}</p>
  ${renderNotices(report)}
  ${renderSections(report)}
  <footer>
    <p>${PRIVACY_NOTICE_JA.map(e).join('<br>')}</p>
    <p class="save"><a href="?download=1">このレポートをHTMLとして保存</a><br>
      <small>保存したHTMLには診断結果やテーブル名などが含まれます。共有する場合は内容を確認してください。</small></p>
    <p>${options.footerNote ? e(options.footerNote) : `このページはあなたのPCの中だけで表示されています。ターミナルで Ctrl+C を押すか、しばらく再表示しないと、表示用のサーバーは終了します。
      終了したあとも、このページはそのまま見ることができます（再読み込みはできません）。`}</p>
  </footer>
</main>
<script nonce="${nonce}">${SCRIPT}</script>
</body>
</html>`;
}
