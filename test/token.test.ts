// Phase 4.8: アクセストークン作成の案内（4ステップ）・貼り付け時の確認・エラーの直し方のテスト。

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import vm from 'node:vm';
import { supabaseTokenPage, SUPABASE_TOKENS_URL } from '../src/app/pages.js';
import { explainTokenProblem } from '../src/app/token-guide.js';
import { isAllowedExternalUrl } from '../src/shared/url.js';
import { SupabaseApiError } from '../src/supabase/errors.js';
import { checkTokenInput } from '../src/supabase/token-check.js';

// テスト用と分かる値（TEST_ONLY / DUMMY / NOT_REAL を含む）
const SCOPED = 'sbp_fc_TEST_ONLY_DUMMY_NOT_REAL_0000000000';
const LEGACY = 'sbp_TEST_ONLY_DUMMY_NOT_REAL_LEGACY_00000';
const REF = 'abcdefghijklmnopqrst';
const SECRET_PART = 'TEST_ONLY_DUMMY';

describe('貼り付けたトークンの確認（Supabase には問い合わせない）', () => {
  it('範囲を絞ったトークン（sbp_fc）は ok', () => {
    const r = checkTokenInput(SCOPED);
    assert.equal(r.status, 'ok');
    assert.equal(r.kind, 'scoped');
    assert.equal(r.token, SCOPED);
    assert.deepEqual(r.fixed, []);
  });

  it('空白・改行・全角・ゼロ幅文字・引用符・Bearer・SUPABASE_ACCESS_TOKEN= は取り除き、直したことを伝える', () => {
    for (const input of [
      `  ${SCOPED}\n`,
      `${SCOPED.slice(0, 10)} ${SCOPED.slice(10)}`,
      `"${SCOPED}"`,
      `Bearer ${SCOPED}`,
      `SUPABASE_ACCESS_TOKEN=${SCOPED}`,
      `\u200b${SCOPED}\ufeff`,
      SCOPED.replace('sbp', 'ｓｂｐ'),
    ]) {
      const r = checkTokenInput(input);
      assert.equal(r.token, SCOPED, JSON.stringify(input));
      assert.equal(r.status, 'ok', JSON.stringify(input));
      assert.ok(r.fixed.length > 0, JSON.stringify(input));
    }
  });

  it('貼り付けていない・別の鍵・URL・プロジェクトID・省略表示・不正な文字は error で、何を貼るべきかを伝える', () => {
    const cases: [string, RegExp][] = [
      ['', /まだ貼り付けられていません/],
      ['   ', /まだ貼り付けられていません/],
      ['eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.x', /anon key.*service_role key/],
      ['sb_publishable_abcdef', /API キー/],
      ['sb_secret_abcdef', /API キー/],
      ['https://supabase.com/dashboard/project/abcdefghijklmnopqrst', /URL が貼り付けられています/],
      [REF, /プロジェクトID/],
      ['sbp_fc_abcd…', /省略された表示/],
      ['sbp_fc_abcd...', /省略された表示/],
      ['sbp_••••••••', /省略された表示/],
      ['ghp_abcdefghijklmnopqrstuvwxyz', /sbp_ で始まる文字列/],
      ['sbp_fc_abc-def.ghi', /使えない文字/],
    ];
    for (const [input, expected] of cases) {
      const r = checkTokenInput(input);
      assert.ok(r.status === 'error' || r.status === 'empty', input);
      assert.match(r.messages.join('\n'), expected, input);
    }
  });

  it('従来型（Legacy）はおすすめしない warn。短すぎるものは途中切れの可能性を伝える', () => {
    const legacy = checkTokenInput(LEGACY);
    assert.equal(legacy.status, 'warn');
    assert.equal(legacy.kind, 'legacy');
    assert.match(legacy.messages.join('\n'), /おすすめしません/);
    assert.doesNotMatch(legacy.messages.join('\n'), /短すぎ/);
    assert.match(checkTokenInput('sbp_' + '0'.repeat(26)).messages.join('\n'), /途中で切れている可能性/);
    const short = checkTokenInput('sbp_fc_abc');
    assert.equal(short.status, 'warn');
    assert.match(short.messages.join('\n'), /短すぎる/);
  });

  it('どの結果のメッセージにも、トークンの文字は含まれない', () => {
    for (const input of [SCOPED, LEGACY, `${SCOPED}…`, `x${SCOPED}`, `${SCOPED}-`, `  ${SCOPED} `]) {
      const r = checkTokenInput(input);
      for (const m of [...r.messages, ...r.fixed]) assert.ok(!m.includes(SECRET_PART) && !m.includes('0123456789abcdef'), m);
    }
  });

  it('関数のソースを画面に埋め込んでも同じ結果になる（外のものを参照していない）', () => {
    const fn = vm.runInNewContext(`(${checkTokenInput.toString()})`) as typeof checkTokenInput;
    for (const input of ['', SCOPED, ` ${SCOPED} `, LEGACY, 'eyJx', REF, 'sbp_fc_abc…']) {
      assert.deepEqual(JSON.parse(JSON.stringify(fn(input))), JSON.parse(JSON.stringify(checkTokenInput(input))), input);
    }
  });
});

describe('4ステップの案内画面', () => {
  const base = '/r/0123456789abcdef0123456789abcdef/';
  const html = supabaseTokenPage({ base, connectTicket: 't'.repeat(32), csrf: 'c'.repeat(48), nonce: 'n', path: 'C:\\app', refs: [REF] });
  const text = html.replace(/<script[\s\S]*?<\/script>/g, '').replace(/<style[\s\S]*?<\/style>/g, '').replace(/<[^>]+>/g, ' ');

  it('4つのステップで、最初に「合言葉」として説明してから「アクセストークン」という名前を出す', () => {
    for (const n of ['1', '2', '3', '4']) assert.match(html, new RegExp(`<span class="step-no">${n}</span>`));
    const firstToken = text.indexOf('アクセストークン');
    assert.ok(text.indexOf('専用の合言葉') >= 0 && text.indexOf('専用の合言葉') < firstToken, '専門用語の前に説明がある');
    assert.doesNotMatch(text, /\bPAT\b|Personal Access Token/i);
  });

  it('作成ページを既定のブラウザで開くボタンがあり、そのURLは外部で開いてよいリンク', () => {
    assert.match(html, new RegExp(`<a class="btn" href="${SUPABASE_TOKENS_URL}" target="_blank" rel="noopener noreferrer">Supabase の作成ページをブラウザで開く</a>`));
    assert.equal(isAllowedExternalUrl(SUPABASE_TOKENS_URL), true);
    assert.match(html, /Supabase のページを開いて削除する/);
  });

  it('対象のプロジェクト・Advisors の Read・有効期限の3点を、具体的に案内する', () => {
    assert.match(text, /対象のプロジェクト .*このアプリのプロジェクト（ abcdefghijklmnopqrst ）だけ/);
    assert.match(text, /「Advisors」を「Read」/);
    assert.match(text, /ほかの権限は付けない/);
    assert.match(text, /有効期限 .*できるだけ短く/);
    assert.match(text, /無期限（Never）」は選ばない/);
    assert.match(text, /Legacy.*おすすめしません/);
  });

  it('保存しない・作者のサーバーに送らないことを伝え、トークンの欄は値を持たないパスワード欄', () => {
    assert.match(text, /保存しません/);
    assert.match(text, /作者のサーバーにも送りません/);
    assert.match(html, /<input type="password" id="token" name="token" autocomplete="off" spellcheck="false" placeholder="sbp_...">/);
  });

  it('プロジェクトが分からない場合・複数ある場合も、選び方を案内する', () => {
    const none = supabaseTokenPage({ base, connectTicket: 't'.repeat(32), csrf: 'c', nonce: 'n', path: 'p', refs: [] });
    assert.match(none, /「すべてのプロジェクト」は選ばない/);
    const many = supabaseTokenPage({ base, connectTicket: 't'.repeat(32), csrf: 'c', nonce: 'n', path: 'p', refs: [REF, 'bbbbbbbbbbbbbbbbbbbb'] });
    assert.match(many, /abcdefghijklmnopqrst<\/code> または <code>bbbbbbbbbbbbbbbbbbbb/);
  });

  it('従来型の確認欄は、必要なときだけ表示する', () => {
    assert.match(html, /<p class="legacy-confirm" id="legacy-confirm">/);
    const ask = supabaseTokenPage({ base, connectTicket: 't'.repeat(32), csrf: 'c', nonce: 'n', path: 'p', refs: [REF], askLegacy: true, tokenNotice: { status: 'warn', messages: ['x'] } });
    assert.match(ask, /<p class="legacy-confirm on" id="legacy-confirm">/);
  });
});

describe('Supabase の応答ごとの直し方', () => {
  const err = (kind: ConstructorParameters<typeof SupabaseApiError>[0], status: number) => new SupabaseApiError(kind, '/v1/projects/x/advisors/security', 'x', status);

  it('401：無効。コピーの途中切れ・作り直しを案内する', () => {
    const p = explainTokenProblem(err('invalid_token', 401), REF);
    assert.match(p.title, /無効/);
    assert.match(p.fixes.join('\n'), /途中で切れていないか/);
    assert.equal(p.recreate, true);
  });

  it('403：権限不足。Advisors の Read と、対象のプロジェクト（ID付き）を確かめるよう案内する', () => {
    const p = explainTokenProblem(err('forbidden', 403), REF);
    assert.match(p.title, /権限が足りません/);
    assert.match(p.fixes.join('\n'), /「Advisors」を「Read」/);
    assert.match(p.fixes.join('\n'), new RegExp(`このアプリのプロジェクト（${REF}）を選んだか`));
  });

  it('404：プロジェクト違い。対象に含めていないと見つからないことがあると案内する', () => {
    const p = explainTokenProblem(err('not_found', 404), REF);
    assert.match(p.title, new RegExp(REF));
    assert.match(p.fixes.join('\n'), /対象に含めていないプロジェクト/);
  });

  it('通信エラーなどは、従来の説明を使う（作り直しは案内しない）', () => {
    const p = explainTokenProblem(err('network', 0), REF);
    assert.match(p.title, /接続できませんでした/);
    assert.equal(p.recreate, false);
  });
});
