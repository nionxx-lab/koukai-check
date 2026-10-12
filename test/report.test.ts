import assert from 'node:assert/strict';
import { request } from 'node:http';
import { describe, it } from 'node:test';
import { diagnoseAdvisorResponse } from '../src/diagnostics/index.js';
import { escapeHtml, escapeWithInlineCode, safeHref } from '../src/report/escape.js';
import { INCOMPLETE_NOTICE_JA, PRIVACY_NOTICE_JA, renderReportHtml } from '../src/report/html.js';
import { createNonce, startReportServer } from '../src/report/server.js';
import { describeObservedAt, formatJst } from '../src/report/time.js';
import { describeToken } from '../src/supabase/token.js';
import type { DiagnosticReport } from '../src/types/diagnostic.js';

type RawLint = Record<string, unknown>;

function lint(name: string, overrides: RawLint = {}): RawLint {
  return {
    name,
    title: name,
    level: 'ERROR',
    facing: 'EXTERNAL',
    categories: ['SECURITY'],
    description: `Description of ${name}`,
    detail: `Detail of ${name}`,
    remediation: 'https://supabase.com/docs/guides/database/database-linter',
    metadata: { schema: 'public', name: 'profiles', type: 'table' },
    cache_key: `${name}_public_profiles`,
    ...overrides,
  };
}

function reportOf(lints: unknown[], token?: string): DiagnosticReport {
  const r = diagnoseAdvisorResponse({ lints }, token ? { token: describeToken(token) } : {});
  assert.ok(r);
  return r;
}

const NONCE = 'test-nonce';
const FETCHED_AT = new Date('2026-10-07T09:30:00Z');

function render(report: DiagnosticReport): string {
  return renderReportHtml(report, { nonce: NONCE, fetchedAt: FETCHED_AT, projectRef: 'abcdefghijklmnopqrst' });
}

describe('HTMLエスケープ', () => {
  it('escapeHtml は HTML の特殊文字をすべて置換する', () => {
    assert.equal(escapeHtml(`<a href="x" onclick='y'>&\`</a>`), '&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;&#96;&lt;/a&gt;');
  });

  it('escapeWithInlineCode はバッククォート部分を <code> にし、中身もエスケープする', () => {
    assert.equal(escapeWithInlineCode('`public.profiles` テーブル'), '<code>public.profiles</code> テーブル');
    assert.equal(escapeWithInlineCode('`<b>x</b>` & y'), '<code>&lt;b&gt;x&lt;/b&gt;</code> &amp; y');
    assert.equal(escapeWithInlineCode('閉じていない `<i>'), '閉じていない &#96;&lt;i&gt;');
  });

  it('safeHref は https 以外を拒否する', () => {
    assert.equal(safeHref('javascript:alert(1)'), undefined);
    assert.equal(safeHref('http://example.com'), undefined);
    assert.equal(safeHref('data:text/html,x'), undefined);
    assert.equal(safeHref('https://supabase.com/docs?a=1&b=2'), 'https://supabase.com/docs?a=1&amp;b=2');
  });

  it('テーブル名・スキーマ名・Advisorの文字列に含まれるタグを実行可能な形で出力しない', () => {
    const evil = '<script>alert(1)</script>';
    const evilAttr = '"><img src=x onerror=alert(1)>';
    const html = render(
      reportOf([
        lint('rls_disabled_in_public', {
          detail: `Table ${evil}`,
          metadata: { schema: evilAttr, name: evil, type: 'table' },
        }),
        lint(`unknown_${evil}`, { title: evil, detail: evilAttr, metadata: { schema: 'public', name: evilAttr, type: 'table' } }),
      ]),
    );
    assert.ok(!html.includes(evil), '生の <script> が含まれている');
    assert.ok(!html.includes('<img'), '生の <img> が含まれている');
    assert.ok(!html.includes('onerror=alert(1)>'), '属性を閉じる文字列がそのまま含まれている');
    assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
    // 自分の <script> は末尾の1つだけ（nonce付き）
    assert.equal(html.match(/<script/g)?.length, 1);
    assert.ok(html.includes(`<script nonce="${NONCE}">`));
  });

  it('remediation が https 以外ならリンクを出さない', () => {
    const html = render(reportOf([lint('rls_disabled_in_public', { remediation: 'javascript:alert(1)' })]));
    assert.doesNotMatch(html, /href="javascript:/i);
    assert.ok(!html.includes('Supabase公式の解説を開く'));
    // 元データは「技術的な詳細」にテキストとして表示されるだけ（リンクにはしない）
    assert.ok(html.includes('&quot;remediation&quot;: &quot;javascript:alert(1)&quot;'));
  });
});

describe('外部リソースを使わない', () => {
  const html = render(reportOf([lint('rls_disabled_in_public'), lint('security_definer_view', { metadata: { schema: 'public', name: 'v', type: 'view' } })]));

  it('CSP を meta で設定し、通信・外部読み込みを禁止する', () => {
    assert.match(html, /<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;nonce-test-nonce&#39;; script-src &#39;nonce-test-nonce&#39;; img-src &#39;none&#39;; font-src &#39;none&#39;; connect-src &#39;none&#39;/);
  });

  it('外部スクリプト・スタイル・フォント・画像を読み込まない', () => {
    assert.doesNotMatch(html, /<script[^>]+src=/);
    assert.doesNotMatch(html, /<link\b/);
    assert.doesNotMatch(html, /<img\b|<iframe\b|@import|url\(/);
    // 外部URLは公式解説へのリンク（ユーザーがクリックしたときだけ開く）に限られる
    const urls = html.match(/https?:\/\/[^\s"'<)]+/g) ?? [];
    for (const url of urls) assert.match(url, /^https:\/\/supabase\.com\//, url);
    assert.match(html, /target="_blank" rel="noopener noreferrer"/);
  });
});

describe('レポートの最上部', () => {
  it('危険あり → 修正してから公開', () => {
    const html = render(reportOf([lint('rls_disabled_in_public')]));
    assert.match(html, /<p class="verdict v-danger">修正してから公開することをおすすめします<\/p>/);
  });

  it('危険0・要確認あり → 確認してから公開', () => {
    const html = render(reportOf([lint('rls_enabled_no_policy', { level: 'INFO' })]));
    assert.match(html, /いくつか確認してから公開することをおすすめします/);
  });

  it('危険・要確認なし → 大きな問題は見つかりませんでした（「安全」とは言わない）', () => {
    for (const lints of [[], [lint('extension_in_public', { metadata: { schema: 'public', name: 'pgcrypto', type: 'extension' } })]]) {
      const html = render(reportOf(lints));
      assert.match(html, /大きな問題は見つかりませんでした/);
      assert.doesNotMatch(html, /安全です|安全性に問題ありません/);
      assert.match(html, /このツールですべてのセキュリティ問題を検出できるわけではありません。/);
    }
  });
});

describe('サマリーと取得時刻', () => {
  it('件数を表示する', () => {
    const html = render(
      reportOf([
        lint('rls_disabled_in_public'),
        lint('policy_exists_rls_disabled', { metadata: { schema: 'public', name: 'posts', type: 'table' } }),
        lint('rls_enabled_no_policy', { metadata: { schema: 'public', name: 'notes', type: 'table' } }),
        lint('extension_in_public', { metadata: { schema: 'public', name: 'pgcrypto', type: 'extension' } }),
      ]),
    );
    assert.match(html, /🔴 危険<b>2<\/b>件/);
    assert.match(html, /🟠 要確認<b>1<\/b>件/);
    assert.match(html, /🔵 参考<b>1<\/b>件/);
  });

  it('日本時間で表示する', () => {
    assert.equal(formatJst('2026-10-07T09:00:00Z'), '2026年10月7日 18:00');
    assert.equal(formatJst('2026-12-31T15:30:00Z'), '2027年1月1日 00:30');
    assert.equal(formatJst('not a date'), undefined);
  });

  it('observed_at が1つ／複数／なしの場合', () => {
    assert.equal(
      describeObservedAt({ earliest: '2026-10-07T09:00:00Z', latest: '2026-10-07T09:00:00Z' }, FETCHED_AT),
      '2026年10月7日 18:00（日本時間）時点のSupabaseの診断結果です。',
    );
    assert.equal(
      describeObservedAt({ earliest: '2026-10-07T08:00:00Z', latest: '2026-10-07T09:00:00Z' }, FETCHED_AT),
      '2026年10月7日 17:00 〜 2026年10月7日 18:00（日本時間）のSupabaseの診断結果です。',
    );
    assert.equal(describeObservedAt({}, FETCHED_AT), 'Supabaseから 2026年10月7日 18:30（日本時間）に取得した診断結果です。');
    const html = render(reportOf([lint('rls_disabled_in_public', { observed_at: '2026-10-07T09:00:00Z' })]));
    assert.match(html, /診断結果の取得時刻: 2026年10月7日 18:00（日本時間）時点/);
  });
});

describe('診断カード', () => {
  const html = render(
    reportOf([
      lint('extension_in_public', { metadata: { schema: 'public', name: 'pgcrypto', type: 'extension' } }),
      lint('rls_enabled_no_policy', { metadata: { schema: 'public', name: 'notes', type: 'table' } }),
      lint('rls_disabled_in_public'),
      lint('sensitive_columns_exposed', { metadata: { schema: 'public', name: 'profiles', type: 'table', sensitive_columns: ['email'] } }),
    ]),
  );

  it('危険 → 要確認 → 参考 の順に並ぶ', () => {
    const iDanger = html.indexOf('危険：公開前に確認・修正してください');
    const iReview = html.indexOf('要確認：意図した設定か確認してください');
    const iInfo = html.indexOf('参考：知っておくと安心な項目');
    assert.ok(iDanger > 0 && iDanger < iReview && iReview < iInfo);
  });

  it('各カードに必須項目がある', () => {
    const cards = html.split('<article ').slice(1);
    assert.equal(cards.length, 4);
    for (const card of cards) {
      for (const text of ['class="badge"', '<h3>', '対象:', 'なぜ問題なのか', '公開前にどうすべきか', '修正方針', 'AIに修正を頼む指示をコピー', 'Supabase公式の解説を開く', '技術的な詳細を見る']) {
        assert.ok(card.includes(text), `カードに「${text}」がない`);
      }
    }
  });

  it('同じ対象の指摘は統合せず、相互にリンクする', () => {
    assert.match(html, /同じ対象への別の指摘/);
    assert.match(html, /<code>public\.profiles<\/code>（テーブル）/);
  });

  it('AI修正指示は readonly textarea にエスケープして入れ、ボタンと対応づける', () => {
    const buttons = html.match(/data-target="(prompt-\d+)"/g) ?? [];
    const areas = html.match(/<textarea id="prompt-\d+" readonly/g) ?? [];
    assert.equal(buttons.length, 4);
    assert.equal(areas.length, 4);
    assert.match(html, /<textarea id="prompt-1" readonly rows="14">Supabaseプロジェクトの&#96;public\.profiles&#96; テーブルについて/);
  });

  it('Raw JSON は「技術的な詳細」の中だけに出す', () => {
    const firstCard = html.split('<article ')[1] ?? '';
    const beforeDetails = firstCard.split('<details class="tech">')[0] ?? '';
    assert.ok(!beforeDetails.includes('cache_key'));
    assert.ok(firstCard.includes('&quot;cache_key&quot;'));
  });
});

describe('不完全な診断・未知の項目・Legacy トークン', () => {
  const banner = INCOMPLETE_NOTICE_JA[0] ?? '';

  it('問題のない結果では注意書きを出さない', () => {
    assert.ok(!render(reportOf([lint('rls_disabled_in_public')])).includes(banner));
  });

  it('解析できなかった項目があれば上部に注意書きを出す', () => {
    const html = render(reportOf(['broken']));
    assert.ok(html.includes(banner));
    assert.ok(html.includes('「問題なし」とは判断しないでください。'));
    assert.match(html, /1 件を読み取れませんでした/);
    assert.ok(html.indexOf(banner) < html.indexOf('<footer>'));
  });

  it('未知の Advisor があれば注意書きと名前を出し、カードも隠さない', () => {
    const html = render(reportOf([lint('brand_new_lint')]));
    assert.ok(html.includes(banner));
    assert.match(html, /<code>brand_new_lint<\/code>/);
    assert.match(html, /Supabaseから新しい診断項目が返されました/);
  });

  it('診断を実行できなかった項目があれば注意書きを出す', () => {
    const html = render(reportOf([lint('advisor_check_unavailable', { categories: ['HEALTH'], metadata: {} })]));
    assert.ok(html.includes(banner));
    assert.match(html, /Supabase側で実行できなかった診断があります/);
  });

  it('Legacy トークンの警告を出すが、トークンの値は埋め込まない', () => {
    const token = 'sbp_TEST_ONLY_DUMMY_NOT_REAL_LEGACY_TOKEN';
    const html = render(reportOf([lint('rls_disabled_in_public')], token));
    assert.match(html, /このトークンは広い権限を持っています。/);
    assert.match(html, /Advisors: Read/);
    assert.ok(!html.includes(token));
    assert.ok(!html.includes('sbp_TEST'));
  });

  it('Scoped トークンでは警告を出さない', () => {
    const html = render(reportOf([lint('rls_disabled_in_public')], 'sbp_fc_scoped'));
    assert.ok(!html.includes('このトークンは広い権限を持っています。'));
  });
});

describe('プライバシー表示', () => {
  it('下部に送信しない旨を表示する', () => {
    const html = render(reportOf([]));
    for (const line of PRIVACY_NOTICE_JA) assert.ok(html.includes(line));
    assert.match(PRIVACY_NOTICE_JA.join(''), /作者のサーバーへ送信しません/);
  });
});

// ───────────── ローカルサーバー ─────────────

function get(url: string, options: { host?: string; method?: string } = {}): Promise<{ status: number; headers: Record<string, unknown>; body: string }> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = request(
      { hostname: u.hostname.replace(/^\[|\]$/g, ""), port: u.port, path: u.pathname + u.search, method: options.method ?? 'GET', headers: options.host ? { host: options.host } : {} },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (c) => (body += c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
      },
    );
    req.on('error', reject);
    req.end();
  });
}

describe('ローカルサーバー', () => {
  it('127.0.0.1 で待ち受け、推測できないパスでだけレポートを返す', async () => {
    const nonce = createNonce();
    const server = await startReportServer({ html: '<p>ok</p>', nonce });
    try {
      assert.match(server.url, /^http:\/\/127\.0\.0\.1:\d+\/r\/[0-9a-f]{32}$/);

      const ok = await get(server.url);
      assert.equal(ok.status, 200);
      assert.equal(ok.body, '<p>ok</p>');
      assert.match(String(ok.headers['content-security-policy']), new RegExp(`script-src 'nonce-${nonce.replace(/[+/=]/g, '\\$&')}'`));
      assert.match(String(ok.headers['content-security-policy']), /connect-src 'none'/);
      assert.equal(ok.headers['x-content-type-options'], 'nosniff');
      assert.equal(ok.headers['cache-control'], 'no-store');
      assert.equal(ok.headers['referrer-policy'], 'no-referrer');

      const root = await get(`http://127.0.0.1:${server.port}/`);
      assert.equal(root.status, 404);
      assert.ok(!root.body.includes('ok'));
    } finally {
      await server.close();
    }
  });

  it('Host ヘッダーが 127.0.0.1 / localhost 以外なら拒否する（DNSリバインディング対策）', async () => {
    const server = await startReportServer({ html: 'secret', nonce: 'n' });
    try {
      const evil = await get(server.url, { host: `evil.example:${server.port}` });
      assert.equal(evil.status, 403);
      assert.ok(!evil.body.includes('secret'));
      const localhost = await get(server.url, { host: `localhost:${server.port}` });
      assert.equal(localhost.status, 200);
    } finally {
      await server.close();
    }
  });

  it('GET / HEAD 以外は受け付けない', async () => {
    const server = await startReportServer({ html: 'x', nonce: 'n' });
    try {
      assert.equal((await get(server.url, { method: 'POST' })).status, 405);
    } finally {
      await server.close();
    }
  });

  it('LAN 側のアドレスからは接続できない（loopback のみで待ち受け）', async () => {
    const { networkInterfaces } = await import('node:os');
    const lan = Object.values(networkInterfaces())
      .flat()
      .find((a) => a && a.family === 'IPv4' && !a.internal);
    const server = await startReportServer({ html: 'x', nonce: 'n' });
    try {
      if (!lan) return; // LAN アドレスがない環境では確認できない
      await assert.rejects(get(`http://${lan.address}:${server.port}/`));
    } finally {
      await server.close();
    }
  });
});

// ───────────── Phase 3 追加分（指示書 §16・§17・§20） ─────────────

function decodeHtml(text: string): string {
  return text
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#96;/g, '`')
    .replace(/&amp;/g, '&');
}

describe('クリップボード用データ', () => {
  it('textarea の中身を復元すると、Phase 2 の aiFixPrompt と完全に一致する（XSS文字列を含む場合も）', () => {
    const report = reportOf([
      lint('rls_disabled_in_public', { metadata: { schema: 'public', name: '<b>"x"</b>&`y`', type: 'table' } }),
      lint('rls_enabled_no_policy', { metadata: { schema: 'public', name: 'notes', type: 'table' } }),
    ]);
    const html = render(report);
    report.diagnostics.forEach((d, i) => {
      const m = html.match(new RegExp(`<textarea id="prompt-${i + 1}" readonly rows="14">([\\s\\S]*?)</textarea>`));
      assert.ok(m, `prompt-${i + 1} がない`);
      assert.equal(decodeHtml(m[1] ?? ''), d.aiFixPrompt);
      assert.ok(!(m[1] ?? '').includes('</textarea'), 'textarea を閉じる文字列が含まれていない');
    });
  });
});

describe('HTML生成時に外部通信しない', () => {
  it('fetch を使えない状態でもレポートを生成でき、通信を要求しない', () => {
    const original = globalThis.fetch;
    let called = 0;
    globalThis.fetch = (async () => {
      called++;
      throw new Error('network is not allowed');
    }) as typeof fetch;
    try {
      const html = render(reportOf([lint('rls_disabled_in_public'), lint('brand_new_lint')]));
      assert.match(html, /公開前チェック結果/);
      assert.equal(called, 0);
    } finally {
      globalThis.fetch = original;
    }
  });
});

describe('HTMLとして保存', () => {
  it('レポートに保存リンクと注意書きがある', () => {
    const html = render(reportOf([]));
    assert.match(html, /<a href="\?download=1">このレポートをHTMLとして保存<\/a>/);
    assert.match(html, /保存したHTMLには診断結果やテーブル名などが含まれます。共有する場合は内容を確認してください。/);
    assert.match(html, /終了したあとも、このページはそのまま見ることができます/);
  });

  it('?download=1 のときだけ添付ファイルとして同じHTMLを返す', async () => {
    const server = await startReportServer({ html: '<p>same</p>', nonce: 'n' });
    try {
      const normal = await get(server.url);
      assert.equal(normal.headers['content-disposition'], undefined);
      const download = await get(`${server.url}?download=1`);
      assert.equal(download.status, 200);
      assert.equal(download.body, '<p>same</p>');
      assert.equal(download.headers['content-disposition'], 'attachment; filename="koukai-check-report.html"');
      assert.match(String(download.headers['content-security-policy']), /default-src 'none'/);
    } finally {
      await server.close();
    }
  });
});

describe('ローカルサーバーの待ち受けと自動終了用の通知', () => {
  it('待ち受けアドレスは 127.0.0.1 のみ', async () => {
    const server = await startReportServer({ html: 'x', nonce: 'n' });
    try {
      assert.equal(new URL(server.url).hostname, '127.0.0.1');
      // localhost の別名（::1 など）では待ち受けていない
      await assert.rejects(get(`http://[::1]:${server.port}/`));
    } finally {
      await server.close();
    }
  });

  it('レポート本体を返したときだけ onReportServed を呼ぶ（404・403では呼ばない）', async () => {
    let served = 0;
    const server = await startReportServer({ html: 'x', nonce: 'n', onReportServed: () => served++ });
    try {
      await get(`http://127.0.0.1:${server.port}/`);
      await get(server.url, { host: 'evil.example' });
      assert.equal(served, 0);
      await get(server.url);
      assert.equal(served, 1);
    } finally {
      await server.close();
    }
  });
});
