// 起動方法の振り分け。
//   koukai-check                 → 一般ユーザー向けの画面（フォルダを選ぶ）
//   koukai-check --no-open       → 同上（ブラウザを自動で開かない）
//   koukai-check supabase [...]  → 開発用の Supabase 診断CLI（従来の流れ）
//   koukai-check --project … / --from-file … など従来のオプション → 互換のため Supabase 診断CLI
//   koukai-check --help          → 使い方
//   koukai-check --dev-window-host=<path>  → 開発・テスト用：専用ウィンドウの代わりに <path> を起動する（案内には出さない）

export type Mode = { kind: 'app'; noOpen: boolean; windowHost?: string } | { kind: 'cli'; argv: string[] } | { kind: 'help' };

export function chooseMode(argv: string[]): Mode {
  if (argv[0] === 'supabase') return { kind: 'cli', argv: argv.slice(1) };
  if (argv.length === 1 && (argv[0] === '--help' || argv[0] === '-h')) return { kind: 'help' };
  if (argv.every((a) => a === '--no-open')) return { kind: 'app', noOpen: argv.length > 0 };
  const dev = argv.length === 1 ? /^--dev-window-host=(.+)$/.exec(argv[0] ?? '') : null;
  if (dev?.[1]) return { kind: 'app', noOpen: false, windowHost: dev[1] };
  return { kind: 'cli', argv };
}

export const MAIN_HELP = [
  '使い方:',
  '  npx koukai-check                チェックするアプリのフォルダを選ぶ画面を開きます（おすすめ）',
  '  npx koukai-check --no-open      画面のURLだけを表示します（ブラウザを自動で開かない）',
  '',
  '開発者向け:',
  '  npx koukai-check supabase [オプション]   Supabase の診断だけをターミナルから実行します',
  '  npx koukai-check supabase --help         そのオプションの説明',
].join('\n');
