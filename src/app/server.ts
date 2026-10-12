// フォルダ選択から始まるアプリ画面のローカルサーバー。
//
// 既存のレポート用サーバー（report/server.ts）と同じ安全対策を取る:
// ・127.0.0.1 だけで待ち受ける／URLに推測できないパス（/r/<128ビットの乱数>/）を付ける
// ・Host ヘッダーを検査する（DNSリバインディング対策）
// ・ファイルを配信しない（HTMLはすべてメモリ上で組み立てる）
// 追加の対策（フォーム送信を受けるため）:
// ・POST は Origin が自分自身のときだけ受け付け、フォームに埋めた乱数（csrf）も照合する
// ・本文の大きさに上限を設ける
// ・トークンは POST の本文でだけ受け取り、URL・ログ・画面には出さない

import { randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { buildChecks } from '../checks/build.js';
import { extractProjectRef } from '../cli/project-ref.js';
import { scanProject, ScanError, type ScanResult } from '../detect/scan.js';
import { buildDiagnosticReport } from '../diagnostics/classify.js';
import { renderReportHtml } from '../report/html.js';
import { DOWNLOAD_FILENAME, LISTEN_HOST } from '../report/server.js';
import type { ManagementClient } from '../supabase/client.js';
import { SupabaseApiError } from '../supabase/errors.js';
import { describeToken } from '../supabase/token.js';
import { checkTokenInput } from '../supabase/token-check.js';
import type { PickResult } from './folder-picker.js';
import { appContentSecurityPolicy, homePage, messagePage, q, scanPage, supabaseTokenPage, type TokenPageOptions } from './pages.js';
import { explainTokenProblem } from './token-guide.js';

export interface AppServerDeps {
  nonce: string;
  pickFolder(): Promise<PickResult>;
  createClient(token: string): Pick<ManagementClient, 'getSecurityAdvisors'>;
  scan?: (path: string) => ScanResult;
  now(): Date;
  /** 画面が表示されたとき（自動終了までの時間を延ばす） */
  onActivity?(): void;
  /** 画面の「終了する」が押されたとき */
  onQuit?(): void;
  /** テスト用 */
  port?: number;
}

export interface AppServer {
  url: string;
  port: number;
  close(): Promise<void>;
}

const MAX_BODY_BYTES = 16 * 1024;
const MAX_REPORTS = 20;
/** Supabase へ接続する確認の札。画面を出すたびに発行し、接続の直前に1回だけ消費する */
const MAX_CONNECT_TICKETS = 20;
const CONNECT_TICKET_TTL_MS = 30 * 60 * 1000;
const MAX_PATH_LENGTH = 4096;

function headers(nonce: string): Record<string, string> {
  return {
    'Content-Security-Policy': appContentSecurityPolicy(nonce),
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    // no-referrer だとブラウザが同じサイトへのフォーム送信でも Origin: null を送り、CSRF対策の Origin 確認ができない。
    // same-origin なら外部サイトへは送らず、自分自身への送信では Origin が付く。
    'Referrer-Policy': 'same-origin',
    'Cache-Control': 'no-store',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
  };
}

function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

type BodyResult = { kind: 'ok'; form: URLSearchParams } | { kind: 'too-large' } | { kind: 'invalid' };

function readBody(req: IncomingMessage): Promise<BodyResult> {
  return new Promise((resolve) => {
    const type = req.headers['content-type'] ?? '';
    if (!type.startsWith('application/x-www-form-urlencoded')) {
      req.resume();
      resolve({ kind: 'invalid' });
      return;
    }
    let size = 0;
    let tooLarge = false;
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) tooLarge = true; // 読み捨てて、最後に 413 を返す
      else chunks.push(c);
    });
    req.on('end', () => resolve(tooLarge ? { kind: 'too-large' } : { kind: 'ok', form: new URLSearchParams(Buffer.concat(chunks).toString('utf8')) }));
    req.on('error', () => resolve({ kind: 'invalid' }));
  });
}

export async function startAppServer(deps: AppServerDeps): Promise<AppServer> {
  const secret = randomBytes(16).toString('hex');
  const base = `/r/${secret}/`;
  const csrf = randomBytes(24).toString('hex');
  const reports = new Map<string, string>();
  // 確認の札はメモリにだけ持つ（保存しないので、再起動すると古い確認は使えない）。
  // 値はトークンとは無関係な乱数で、トークンを再送防止のキーには使わない。
  const connectTickets = new Map<string, number>();
  function issueConnectTicket(): string {
    const ticket = randomBytes(16).toString('hex');
    connectTickets.set(ticket, Date.now() + CONNECT_TICKET_TTL_MS);
    while (connectTickets.size > MAX_CONNECT_TICKETS) connectTickets.delete(connectTickets.keys().next().value as string);
    return ticket;
  }
  /** 札を1回だけ使う。見つけた時点で消す（await を挟まないので、同じ札の並行送信でも通るのは1件だけ） */
  function consumeConnectTicket(ticket: string): boolean {
    const expiresAt = connectTickets.get(ticket);
    if (expiresAt === undefined) return false;
    connectTickets.delete(ticket);
    return expiresAt > Date.now();
  }
  let picking = false;
  let allowedHosts = new Set<string>();
  let allowedOrigins = new Set<string>();
  const scan = deps.scan ?? ((p: string) => scanProject(p));
  const H = headers(deps.nonce);

  const send = (res: ServerResponse, status: number, body: string, extra: Record<string, string> = {}) => {
    const buf = Buffer.from(body, 'utf8');
    res.writeHead(status, { ...H, 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': String(buf.length), ...extra });
    res.end(buf);
  };
  const redirect = (res: ServerResponse, location: string) => {
    res.writeHead(303, { ...H, Location: location, 'Content-Length': '0' });
    res.end();
  };
  const text = (res: ServerResponse, status: number, msg: string) => {
    res.writeHead(status, { ...H, 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(msg);
  };

  function scanOrMessage(path: string): { scan: ScanResult } | { error: string } {
    if (!path || path.length > MAX_PATH_LENGTH) return { error: 'not-found' };
    try {
      return { scan: scan(path) };
    } catch (error) {
      return { error: error instanceof ScanError ? error.kind : 'unreadable' };
    }
  }

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!allowedHosts.has(req.headers.host ?? '')) return text(res, 403, 'Forbidden');
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (!url.pathname.startsWith(base)) return text(res, 404, 'Not Found');
    const route = url.pathname.slice(base.length);

    if (req.method === 'POST') {
      const origin = req.headers.origin ?? '';
      if (!allowedOrigins.has(origin)) return text(res, 403, 'Forbidden');
      const body = await readBody(req);
      if (body.kind === 'too-large') return text(res, 413, 'Payload Too Large');
      if (body.kind !== 'ok' || !safeEqual(body.form.get('csrf') ?? '', csrf)) return text(res, 403, 'Forbidden');
      const form = body.form;

      if (route === 'pick') {
        if (picking) return redirect(res, `${base}?msg=busy`);
        picking = true;
        try {
          const picked = await deps.pickFolder();
          if (picked.kind === 'picked') return redirect(res, `${base}scan?path=${q(picked.path)}`);
          return redirect(res, `${base}?msg=${picked.kind}`);
        } finally {
          picking = false;
        }
      }

      if (route === 'supabase/run') {
        const path = form.get('path') ?? '';
        const checked = checkTokenInput(form.get('token') ?? '');
        const refInput = form.get('ref') ?? '';
        const scanned = scanOrMessage(path);
        const refs = 'scan' in scanned ? scanned.scan.supabaseRefs : [];
        const page = (extra: Partial<TokenPageOptions>) =>
          send(res, 200, supabaseTokenPage({ base, csrf, nonce: deps.nonce, path, refs, ref: refs.length === 0 ? refInput.slice(0, 300) : refInput, connectTicket: issueConnectTicket(), ...extra }));

        const ref = extractProjectRef(refInput);
        if (!ref) return page({ error: 'プロジェクトを読み取れませんでした。Supabase のダッシュボードで対象のプロジェクトを開いたときのURLを貼り付けてください。' });
        // 貼り付けた文字列の確認（Supabase に問い合わせる前に、形の間違いを知らせる）
        if (checked.status === 'empty') return page({ tokenNotice: { status: 'error', messages: ['アクセストークンを貼り付けてください（sbp_ で始まる文字列です）。'] } });
        if (checked.status === 'error') return page({ tokenNotice: { status: 'error', messages: checked.messages } });
        // 従来型（Legacy）は権限が強すぎるため、確認の印がない限り使わない
        if (checked.kind === 'legacy' && form.get('allowLegacy') !== '1') {
          return page({ tokenNotice: { status: 'warn', messages: checked.messages }, askLegacy: true });
        }
        // Supabase へ接続する直前の確認。画面の確認で「接続して診断する」を選んだときだけ接続する
        if (form.get('connectConfirmed') !== '1') {
          return page({
            tokenNotice: { status: 'warn', messages: ['Supabase にはまだ接続していません。「チェックする」を押し、確認の画面で「接続して診断する」を選ぶと診断を始めます。'] },
            askLegacy: checked.kind === 'legacy',
          });
        }
        // 確認は1回限り。同じ確認の再送・並行送信では、診断を重ねて始めない
        if (!consumeConnectTicket(form.get('connectTicket') ?? '')) {
          return page({
            tokenNotice: { status: 'warn', messages: ['この確認は、すでに使われたか期限が切れています。Supabase にはまだ接続していません。もう一度「チェックする」を押し、確認の画面で「接続して診断する」を選んでください。'] },
            askLegacy: checked.kind === 'legacy',
          });
        }
        const token = checked.token;
        try {
          const result = await deps.createClient(token).getSecurityAdvisors(ref);
          const report = buildDiagnosticReport(result, { token: describeToken(token) });
          const id = randomBytes(8).toString('hex');
          const html = renderReportHtml(report, {
            nonce: deps.nonce,
            fetchedAt: deps.now(),
            projectRef: ref,
            backLink: { href: `../scan?path=${q(path)}`, label: 'フォルダのチェック結果に戻る' },
            footerNote:
              'このページはあなたのPCの中だけで表示されています。チェックが終わったら、作ったアクセストークンは Supabase のアクセストークンのページで削除できます。終了するときは、チェック結果の画面の「終了する」を押すか、このウィンドウを閉じてください。',
          });
          reports.set(id, html);
          while (reports.size > MAX_REPORTS) reports.delete(reports.keys().next().value as string);
          return redirect(res, `${base}report/${id}`);
        } catch (error) {
          if (error instanceof SupabaseApiError) return page({ problem: explainTokenProblem(error, ref) });
          return page({ problem: { title: '診断を完了できませんでした。時間をおいてもう一度試してください。', fixes: [], recreate: false } });
        }
      }

      if (route === 'quit') {
        send(res, 200, messagePage({ nonce: deps.nonce, title: '終了しました', body: '公開前チェックを終了しました。この画面は閉じてかまいません。' }));
        deps.onQuit?.();
        return;
      }
      return text(res, 404, 'Not Found');
    }

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { ...H, Allow: 'GET, HEAD, POST', 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Method Not Allowed');
      return;
    }
    deps.onActivity?.();

    if (route === '') {
      return send(res, 200, homePage({ base, csrf, nonce: deps.nonce, message: url.searchParams.get('msg') ?? undefined }));
    }

    if (route === 'scan') {
      const scanned = scanOrMessage(url.searchParams.get('path') ?? '');
      if ('error' in scanned) return redirect(res, `${base}?msg=${scanned.error}`);
      return send(res, 200, scanPage({ base, csrf, nonce: deps.nonce, scan: scanned.scan, checks: buildChecks(scanned.scan) }));
    }

    if (route === 'supabase') {
      const scanned = scanOrMessage(url.searchParams.get('path') ?? '');
      if ('error' in scanned) return redirect(res, `${base}?msg=${scanned.error}`);
      // Supabase を使っていないフォルダでは、Supabase の画面を出さない
      if (!scanned.scan.techs.some((t) => t.id === 'supabase')) return redirect(res, `${base}scan?path=${q(scanned.scan.root)}`);
      return send(res, 200, supabaseTokenPage({ base, csrf, nonce: deps.nonce, path: scanned.scan.root, refs: scanned.scan.supabaseRefs, connectTicket: issueConnectTicket() }));
    }

    const m = route.match(/^report\/([0-9a-f]{16})$/);
    if (m?.[1] && reports.has(m[1])) {
      const download = url.searchParams.get('download') === '1';
      return send(res, 200, reports.get(m[1]) ?? '', download ? { 'Content-Disposition': `attachment; filename="${DOWNLOAD_FILENAME}"` } : {});
    }
    return text(res, 404, 'Not Found');
  }

  const server = createServer((req, res) => {
    handle(req, res).catch(() => {
      if (!res.headersSent) text(res, 500, 'Internal Error');
      else res.end();
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(deps.port ?? 0, LISTEN_HOST, () => resolve());
  });
  const { port } = server.address() as AddressInfo;
  allowedHosts = new Set([`${LISTEN_HOST}:${port}`, `localhost:${port}`]);
  allowedOrigins = new Set([`http://${LISTEN_HOST}:${port}`, `http://localhost:${port}`]);

  return {
    url: `http://${LISTEN_HOST}:${port}${base}`,
    port,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}
