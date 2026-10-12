// npx koukai-check の処理の流れ。
// 入出力・通信・サーバー起動は deps 経由で受け取り、テストで差し替えられるようにする。
//
//   プロジェクト指定 → トークン（環境変数 or 非表示入力）→ Security Advisor取得
//   → 診断（ローカル）→ HTML生成 → 127.0.0.1 で配信 → ブラウザを開く → Ctrl+C で終了
//
// トークンはメモリ上でのみ扱い、ファイル・HTML・ログには書かない。

import { buildDiagnosticReport } from '../diagnostics/classify.js';
import { diagnoseAdvisorResponse } from '../diagnostics/index.js';
import { renderReportHtml } from '../report/html.js';
import type { ReportServer, StartOptions } from '../report/server.js';
import type { ManagementClient } from '../supabase/client.js';
import { SupabaseApiError } from '../supabase/errors.js';
import { describeToken } from '../supabase/token.js';
import type { DiagnosticReport } from '../types/diagnostic.js';
import { explainError } from './messages.js';
import { extractProjectRef } from './project-ref.js';
import * as T from './texts.js';

export interface CliDeps {
  argv: string[];
  env: Record<string, string | undefined>;
  print(message: string): void;
  printError(message: string): void;
  ask(question: string): Promise<string>;
  askSecret(question: string): Promise<string>;
  createClient(token: string): Pick<ManagementClient, 'getSecurityAdvisors'>;
  startServer(options: StartOptions): Promise<ReportServer>;
  createNonce(): string;
  openBrowser(url: string): Promise<boolean>;
  readFile(path: string): string;
  /** サーバーを止めてよくなるまで待つ（Ctrl+C、または一定時間レポートが表示されない）。 */
  waitForExit(): Promise<void>;
  /** 自動終了までの分数（案内表示用） */
  idleExitMinutes?: number;
  now(): Date;
}

interface CliArgs {
  project?: string;
  open: boolean;
  fromFile?: string;
  help: boolean;
  /** トークンらしき値がコマンド引数に含まれていた（値そのものは保持しない） */
  tokenInArgs?: boolean;
  /** 使えないオプションが含まれていた（値は表示しない。トークンが紛れている可能性があるため） */
  unknownArgs?: boolean;
}

/** トークンをコマンド引数で受け取る機能は提供しない（シェルの履歴に残るため）。 */
const TOKEN_ARG = /^--?(token|access[-_]?token|pat|supabase[-_]?access[-_]?token)(=|$)/i;

const MAX_PROJECT_ATTEMPTS = 5;
const MAX_TOKEN_ATTEMPTS = 3;

export function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = { open: true, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] ?? '';
    if (TOKEN_ARG.test(a) || /^sbp_/i.test(a)) args.tokenInArgs = true;
    else if (a === '--help' || a === '-h') args.help = true;
    else if (a === '--no-open') args.open = false;
    else if (a === '--project' || a === '--project-ref') args.project = argv[++i];
    else if (a.startsWith('--project=')) args.project = a.slice('--project='.length);
    else if (a.startsWith('--project-ref=')) args.project = a.slice('--project-ref='.length);
    else if (a === '--from-file') args.fromFile = argv[++i];
    else args.unknownArgs = true;
  }
  if (args.project && /^sbp_/i.test(args.project)) args.tokenInArgs = true;
  return args;
}

class ExitError extends Error {
  constructor(message: string, readonly code = 1) {
    super(message);
  }
}

async function askProject(deps: CliDeps): Promise<string> {
  deps.print(T.PROJECT_PROMPT_HELP);
  for (let attempt = 1; attempt <= MAX_PROJECT_ATTEMPTS; attempt++) {
    const ref = extractProjectRef(await deps.ask('URL または プロジェクトID: '));
    if (ref) return ref;
    deps.print(T.PROJECT_INVALID);
  }
  throw new ExitError('プロジェクトを指定できなかったため終了します。');
}

async function askToken(deps: CliDeps): Promise<string> {
  deps.print(T.TOKEN_PROMPT_HELP);
  for (;;) {
    // 全角で入ってしまった英数字は半角に揃える（トークンは英数字と記号のみ）
    const input = (await deps.askSecret('アクセストークン: ')).normalize('NFKC').replace(/[\u200b-\u200d\u2060\ufeff]/g, '').trim();
    if (input === '?' || input === '？') {
      deps.print(T.TOKEN_GUIDE);
      continue;
    }
    if (!input) {
      deps.print('トークンが入力されていません。作り方を見るには「?」と入力してください。');
      continue;
    }
    return input;
  }
}

async function fetchReport(deps: CliDeps, args: CliArgs): Promise<{ report: DiagnosticReport; projectRef: string }> {
  // プロジェクト
  let projectRef: string;
  const projectFromArg = Boolean(args.project);
  if (args.project) {
    const ref = extractProjectRef(args.project);
    if (!ref) throw new ExitError(`--project の値をプロジェクトとして読み取れませんでした。\n${T.PROJECT_INVALID}`);
    projectRef = ref;
  } else {
    projectRef = await askProject(deps);
  }

  // トークン
  const envToken = deps.env.SUPABASE_ACCESS_TOKEN?.trim();
  let token: string;
  if (envToken) {
    deps.print('環境変数 SUPABASE_ACCESS_TOKEN のトークンを使います。');
    token = envToken;
  } else {
    token = await askToken(deps);
  }

  for (let attempt = 1; ; attempt++) {
    const tokenInfo = describeToken(token);
    if (tokenInfo.isBroadAccess) deps.print(`\n⚠ ${T.LEGACY_TOKEN_WARNING}`);
    else if (tokenInfo.noticeJa) deps.print(`\n⚠ ${tokenInfo.noticeJa}`);

    deps.print(`\n${T.CHECKING}`);
    try {
      const result = await deps.createClient(token).getSecurityAdvisors(projectRef);
      return { report: buildDiagnosticReport(result, { token: tokenInfo }), projectRef };
    } catch (error) {
      if (!(error instanceof SupabaseApiError)) throw error;
      deps.print(`\n${explainError(error, 'advisors')}`);

      const canRetryToken = !envToken && attempt < MAX_TOKEN_ATTEMPTS;
      if ((error.kind === 'invalid_token' || error.kind === 'forbidden') && canRetryToken) {
        deps.print('');
        token = await askToken(deps);
        continue;
      }
      if (error.kind === 'not_found' && !projectFromArg && attempt < MAX_PROJECT_ATTEMPTS) {
        deps.print('');
        projectRef = await askProject(deps);
        continue;
      }
      if (envToken && (error.kind === 'invalid_token' || error.kind === 'forbidden')) {
        throw new ExitError('環境変数 SUPABASE_ACCESS_TOKEN のトークンを確認してから、もう一度実行してください。');
      }
      throw new ExitError('診断を完了できませんでした。');
    }
  }
}

function loadReportFromFile(deps: CliDeps, path: string): DiagnosticReport {
  let body: unknown;
  try {
    body = JSON.parse(deps.readFile(path));
  } catch {
    throw new ExitError(`JSONファイルを読み込めませんでした: ${path}`);
  }
  const report = diagnoseAdvisorResponse(body);
  if (!report) throw new ExitError('Security Advisor の結果として読み取れませんでした（"lints" 配列がありません）。');
  return report;
}

function summaryLine(report: DiagnosticReport): string {
  return `${report.headlineJa}（🔴 危険 ${report.counts.danger}件 / 🟠 要確認 ${report.counts.review}件 / 🔵 参考 ${report.counts.info}件）`;
}

export async function runCli(deps: CliDeps): Promise<number> {
  const args = parseArgs(deps.argv);
  if (args.tokenInArgs) {
    deps.printError(T.TOKEN_IN_ARGS);
    return 2;
  }
  if (args.unknownArgs) {
    deps.printError('使えないオプションが指定されました。使い方は npx koukai-check --help で確認できます。');
    return 2;
  }
  if (args.help) {
    deps.print(T.HELP);
    return 0;
  }

  deps.print(T.INTRO);

  let report: DiagnosticReport;
  let projectRef: string | undefined;
  try {
    if (args.fromFile) {
      deps.print('保存済みの診断結果を表示します（Supabaseへは接続しません）。');
      report = loadReportFromFile(deps, args.fromFile);
    } else {
      ({ report, projectRef } = await fetchReport(deps, args));
    }
  } catch (error) {
    if (error instanceof ExitError) {
      deps.printError(`\n${error.message}`);
      return error.code;
    }
    throw error;
  }

  const nonce = deps.createNonce();
  const html = renderReportHtml(report, { nonce, fetchedAt: deps.now(), projectRef });
  const server = await deps.startServer({ html, nonce });

  deps.print(`\n診断が終わりました。${summaryLine(report)}`);
  if (report.incomplete || report.unknownAdvisorNames.length > 0) {
    deps.print('⚠ 確認できなかった項目があります。詳しくはレポートを見てください。');
  }

  const opened = args.open ? await deps.openBrowser(server.url) : false;
  deps.print(opened ? '\nブラウザでレポートを開きました。' : '\n次のURLをブラウザで開くと、レポートを確認できます。');
  deps.print(server.url);
  deps.print('（このPCの中だけで表示されます。終了するには Ctrl+C を押してください）');
  if (deps.idleExitMinutes) {
    deps.print(`最後にレポートを表示してから${deps.idleExitMinutes}分たつと自動で終了します。終了後も、表示中のページはそのまま見られます。`);
  }

  deps.print(`\n${report.disclaimerJa}`);

  try {
    await deps.waitForExit();
  } finally {
    await server.close();
  }
  return 0;
}
