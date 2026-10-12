// レポートを表示するための一時的なローカルHTTPサーバー。
//
// ・127.0.0.1 だけで待ち受ける（LANには公開しない）。ポートはOSに空き番号を選ばせる。
// ・URLに推測できないパス（/r/<ランダム>）を付け、同じPC上の他のプロセスやWebページから読みにくくする。
// ・Host ヘッダーを検査し、DNSリバインディング（外部サイトから127.0.0.1を読ませる攻撃）を防ぐ。
// ・GET / HEAD 以外は受け付けない。外部への通信は一切行わない。

import { randomBytes } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { contentSecurityPolicy } from './html.js';

export const LISTEN_HOST = '127.0.0.1';

export interface ReportServer {
  url: string;
  port: number;
  close(): Promise<void>;
}

export interface StartOptions {
  html: string;
  nonce: string;
  /** テスト用。省略時は 0（OSが空きポートを選ぶ） */
  port?: number;
  /** レポート本体を返したときに呼ぶ（自動終了までの時間を延ばすため） */
  onReportServed?: () => void;
}

export const DOWNLOAD_FILENAME = 'koukai-check-report.html';

export function createNonce(): string {
  return randomBytes(16).toString('base64');
}

function securityHeaders(nonce: string): Record<string, string> {
  return {
    'Content-Security-Policy': contentSecurityPolicy(nonce),
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
  };
}

export async function startReportServer(options: StartOptions): Promise<ReportServer> {
  const secretPath = `/r/${randomBytes(16).toString('hex')}`;
  const body = Buffer.from(options.html, 'utf8');
  let allowedHosts: Set<string> = new Set();

  const handler = (req: IncomingMessage, res: ServerResponse) => {
    const headers = securityHeaders(options.nonce);

    if (!allowedHosts.has(req.headers.host ?? '')) {
      res.writeHead(403, { ...headers, 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Forbidden');
      return;
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { ...headers, Allow: 'GET, HEAD', 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Method Not Allowed');
      return;
    }
    const requestUrl = new URL(req.url ?? '/', 'http://localhost');
    if (requestUrl.pathname !== secretPath) {
      res.writeHead(404, { ...headers, 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not Found');
      return;
    }
    // 「HTMLとして保存」: 同じHTMLを添付ファイルとして返すだけ（新しい情報は含めない）
    const download = requestUrl.searchParams.get('download') === '1';
    res.writeHead(200, {
      ...headers,
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Length': String(body.length),
      ...(download ? { 'Content-Disposition': `attachment; filename="${DOWNLOAD_FILENAME}"` } : {}),
    });
    res.end(req.method === 'HEAD' ? undefined : body);
    options.onReportServed?.();
  };

  const server = createServer(handler);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.port ?? 0, LISTEN_HOST, () => resolve());
  });

  const { port } = server.address() as AddressInfo;
  allowedHosts = new Set([`${LISTEN_HOST}:${port}`, `localhost:${port}`]);

  return {
    url: `http://${LISTEN_HOST}:${port}${secretPath}`,
    port,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}
