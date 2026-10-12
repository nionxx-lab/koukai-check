// テスト実行中の「予期しない外部通信」を検出して失敗させる。
// node --import で全テストプロセス（CLIを起動する子プロセスも含む）に読み込む。
// 許可するのはループバック（127.0.0.1 / ::1 / localhost）と、ローカルのソケットファイルだけ。

import net from 'node:net';
import { networkInterfaces } from 'node:os';

// このPC自身のアドレス（LAN側のアドレスを含む）は外部通信ではないため許可する。
// 「LAN側のアドレスからはレポートに接続できない」ことを確かめるテストで使う。
const OWN_ADDRESSES = Object.values(networkInterfaces())
  .flat()
  .map((a) => a?.address ?? '')
  .filter(Boolean);
const ALLOWED_HOSTS = new Set(['127.0.0.1', '::1', 'localhost', '', ...OWN_ADDRESSES]);

export const violations: string[] = [];

function check(host: unknown, where: string): void {
  const h = typeof host === 'string' ? host.replace(/^\[|\]$/g, '') : '';
  if (!ALLOWED_HOSTS.has(h)) {
    const message = `UNEXPECTED_NETWORK: ${where} -> ${String(host)}`;
    violations.push(message);
    process.stderr.write(`${message}\n`);
    throw new Error(message);
  }
}

const originalConnect = net.Socket.prototype.connect;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
net.Socket.prototype.connect = function patchedConnect(this: net.Socket, ...args: any[]) {
  const first = args[0];
  if (Array.isArray(first)) {
    // 内部的に配列で渡される形式（normalizedArgs）
    const opts = first[0];
    if (opts && typeof opts === 'object' && !('path' in opts && opts.path)) check(opts.host ?? 'localhost', 'socket');
  } else if (first && typeof first === 'object') {
    if (!first.path) check(first.host ?? 'localhost', 'socket');
  } else if (typeof first === 'number' || (typeof first === 'string' && /^\d+$/.test(first))) {
    check(typeof args[1] === 'string' ? args[1] : 'localhost', 'socket');
  }
  // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
  return (originalConnect as (...a: unknown[]) => net.Socket).apply(this, args);
} as typeof net.Socket.prototype.connect;

const originalFetch = globalThis.fetch;
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
  check(url.hostname, 'fetch');
  return originalFetch(input, init);
}) as typeof fetch;
