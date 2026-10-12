#!/usr/bin/env node
// Phase 2 確認用: 保存済みの Security Advisor 応答（JSON）を読み込み、日本語の診断結果を表示する。
// 通信は一切行わない。
//
//   node dist/cli/preview.js                          # 同梱のサンプルを表示
//   node dist/cli/preview.js result.json              # PoC の --raw で保存した応答を表示
//   node dist/cli/preview.js result.json --json       # 診断結果を JSON で出力
//   node dist/cli/preview.js result.json --no-prompt  # AI修正指示を省略

import { readFileSync } from 'node:fs';
import { argv, exit } from 'node:process';
import { fileURLToPath } from 'node:url';
import { diagnoseAdvisorResponse } from '../diagnostics/index.js';
import { formatReport } from './format.js';

const args = argv.slice(2);
const json = args.includes('--json');
const showPrompt = !args.includes('--no-prompt');
const path = args.find((a) => !a.startsWith('--')) ?? fileURLToPath(new URL('../../samples/security-advisors.sample.json', import.meta.url));

let body: unknown;
try {
  body = JSON.parse(readFileSync(path, 'utf8'));
} catch {
  console.error(`JSONファイルを読み込めませんでした: ${path}`);
  exit(1);
}

const report = diagnoseAdvisorResponse(body);
if (!report) {
  console.error('Security Advisor の応答として読み取れませんでした（"lints" 配列がありません）。');
  exit(1);
}

console.log(json ? JSON.stringify(report, null, 2) : formatReport(report, { showPrompt }));
