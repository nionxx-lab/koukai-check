// 判定した技術に応じて、表示するチェックだけを組み立てる（データ駆動）。
// 使っていない技術のチェックは出さない（Supabase を使っていなければ Supabase の画面は出さない）。

import type { ScanResult, TechId } from '../detect/scan.js';
import type { GitState, PrivateKeyLocation, PublicExposure, SecretNameLocation } from '../detect/scan.js';
import type { RuleFinding } from '../detect/firebase-rules.js';
import type { HistoryFinding } from '../detect/git-history.js';
import { SECRET_DEFINITIONS } from '../detect/secret-defs.js';
import type { SecretValueReason } from '../detect/secret-names.js';
import { attachGuide, type FixGuide } from '../explanations/fix-guides.js';

export type CheckStatus =
  | 'danger' // 公開前に直すべき可能性が高い（自動で見つかった）
  | 'warn' // 確認をおすすめ（自動で見つかった）
  | 'ok' // 自動で確認し、問題は見つからなかった（安全の保証ではない）
  | 'action' // 追加の診断へ進める（Supabase）
  | 'manual'; // 自動チェックは未対応。確認のヒントだけを出す

export interface CheckItem {
  id: string;
  tech: TechId;
  status: CheckStatus;
  title: string;
  body: string;
  /** 箇条書きで補足（ファイル名や変数名。値は含めない） */
  points?: string[];
  /** 折りたたんで表示する補足（「参照している場所 ○件」など） */
  details?: { summary: string; items: string[] }[];
  /** 公式の解説（固定のURLだけ） */
  link?: { href: string; label: string };
  /** Supabase 診断へ進む */
  supabase?: { refs: string[] };
  /** 🔴・🟠 の項目の直し方と、AIへの修正依頼文（値・絶対パスは含めない） */
  guide?: FixGuide;
}

export const TECH_LABELS: Record<TechId, { name: string; description: string }> = {
  supabase: { name: 'Supabase', description: 'データベースとログイン機能のサービス' },
  firebase: { name: 'Firebase', description: 'Google のデータベースとログイン機能のサービス' },
  nextjs: { name: 'Next.js', description: 'Webアプリを作るための仕組み' },
  expo: { name: 'Expo', description: 'スマホアプリを作るための仕組み' },
  'react-native': { name: 'React Native', description: 'スマホアプリを作るための仕組み' },
  'external-api': { name: '外部のAPI', description: 'AI・決済・メールなど、外部サービスとの連携' },
  env: { name: '.env ファイル', description: 'APIキーなどの設定を書くファイル' },
  credentials: { name: '認証情報', description: 'APIキー・トークン・パスワードなど、秘密にするもの' },
};

const REASON_LABEL: Record<string, string> = {
  name: '名前が秘密情報らしい',
  'supabase-secret-key': '値が Supabase の秘密キー（sb_secret_）の形',
  'supabase-service-role-jwt': '値が Supabase の service_role キーの形',
  'secret-api-key': '値が外部サービスの秘密キー（sk-… など）の形',
};

function has(scan: ScanResult, id: TechId): boolean {
  return scan.techs.some((t) => t.id === id);
}

const PLACE_LABEL = { env: '.env', 'env-example': '.env の見本', config: '設定ファイル', source: 'ソースコード', other: 'ファイル' } as const;
const GIT_LABEL: Record<GitState, string> = {
  tracked: 'Git で管理されている（公開される）',
  untracked: 'Git にまだ追加されていないが、除外もされていない',
  ignored: 'Git の対象外（.gitignore）',
  'not-ignored': '.gitignore で除外されていない',
  'no-git': 'Git なし',
};
const VALUE_LABEL: Record<SecretValueReason, string> = {
  'token-format': '本物の形式に見える',
  'url-credentials': 'パスワードが入った接続先',
  'private-key': '本物の秘密鍵に見える',
  'key-unverified': '秘密鍵の形だが、本物か確認できない',
  'test-word': 'テスト用の値（TEST・DUMMY などの語を含む）',
  'too-short': 'テスト用の値（本物より短い）',
  'low-randomness': 'テスト用の値（ランダムな文字列ではない）',
  'local-dev': 'ローカル開発用の値',
  'local-unconfirmed': 'ローカル開発用の鍵の形だが、ローカル用だと確認できない',
  'placeholder-pattern': 'ダミー（見本の値）',
  'not-token-format': 'ダミー（形式が違う）',
  'no-credentials': 'パスワードを含まない',
  'public-key': '公開してよいキー',
};

export type SecretRisk = 'danger' | 'warn' | 'info';

/**
 * 1か所ごとの重大度（すべてのサービスで共通）。🔴・🟠にするのは「本物らしい値」が書かれている場合だけ。
 * 参照だけ・ダミー・テスト用・公開してよいキー（Supabase の publishable / anon など）は、漏れではないので数えない。
 * フォルダ名（tests・test-results など）では判断せず、値の形と Git の状態で判断する。
 */
export function secretRisk(h: SecretNameLocation): SecretRisk {
  // 本物かどうか判断できないものは、安全とは扱わず「要確認」にする
  if (h.value?.kind === 'uncertain') return 'warn';
  if (h.value?.kind !== 'real-like') return 'info';
  if (h.usage === 'public-env') return 'danger'; // アプリに埋め込まれて配布される
  if (h.publicDir) return 'danger'; // 公開フォルダ（public/・static/ など）の中は、Git の対象外でも Web から配信されうる
  if (h.git === 'tracked') return 'danger'; // Git で管理されている（コミット済み・追加済み）
  if (h.git === 'untracked' || h.git === 'not-ignored') {
    // .gitignore で除外されていない。ソース・設定ファイルはふつうコミットされるので 🔴、.env は手元に置くことが多いので 🟠
    return h.place === 'env' ? 'warn' : 'danger';
  }
  if (h.git === 'no-git') return 'warn'; // 公開のしかたが分からないため確認が必要
  // Git の対象外（ignored）
  return h.place === 'env' ? 'info' : 'warn'; // .env（Git の対象外）は本来の置き場所
}

function locationText(h: SecretNameLocation): string {
  const value = h.value ? `・${VALUE_LABEL[h.value.reason]}` : '';
  const git = h.value ? `・${GIT_LABEL[h.git]}` : '';
  const generated = h.generated ? '・自動で作られるフォルダの可能性' : '';
  const pub = h.publicDir ? `・公開フォルダ ${h.publicDir}/ の中` : '';
  const as = h.as ? `・変数名 ${h.as}` : '・値の形で検出';
  return `${h.file}:${h.line}（${PLACE_LABEL[h.place]}${value}${git}${pub}${generated}${as}）`;
}

// ───────────── 秘密鍵・サービスアカウント鍵 ─────────────

const KEY_KIND_LABEL: Record<PrivateKeyLocation['kind'], string> = {
  pem: '秘密鍵（PEM 形式）',
  openssh: 'SSH の秘密鍵（OpenSSH 形式）',
  pgp: 'PGP の秘密鍵',
  putty: 'PuTTY の秘密鍵',
  'service-account': 'Google・Firebase のサービスアカウント鍵',
};

/**
 * 秘密鍵の重大度。はっきりしたダミー（見本の文字・同じ値の繰り返し）だけを数えない。
 * Git の扱いは秘密情報と同じ：管理されている・除外されていない → 🔴、Git なし → 🟠、Git の対象外 → 数えない。
 * パスフレーズで暗号化された鍵・本物か判断できない鍵は、🟠 にとどめる（安全とは扱わない）。公開フォルダの中は、公開フォルダの項目で扱う。
 */
export function privateKeyRisk(k: PrivateKeyLocation): SecretRisk {
  if (k.value === 'test-like') return 'info';
  const capped = k.encrypted || k.value === 'uncertain';
  if (k.publicDir) return capped ? 'warn' : 'danger';
  let risk: SecretRisk;
  if (k.git === 'tracked' || k.git === 'untracked' || k.git === 'not-ignored') risk = 'danger';
  else if (k.git === 'no-git') risk = 'warn';
  else risk = 'info';
  if (risk === 'danger' && capped) risk = 'warn';
  return risk;
}

/** 鍵の状態の補足（暗号化・本物か判断できない・復元できない部分がある） */
function keyStateText(k: PrivateKeyLocation): string {
  return (
    (k.encrypted ? '・パスフレーズで暗号化されている' : '') +
    (k.value === 'uncertain' ? '・秘密鍵の形だが、本物か確認できない' : '') +
    (k.unresolved ? '・コードの一部（変数など）を復元できない' : '')
  );
}

const RISK_RANK: Record<SecretRisk, number> = { danger: 2, warn: 1, info: 0 };

/**
 * 名前つきの秘密情報（GitHub App の秘密鍵など）と、秘密鍵の項目が同じ鍵（同じファイルの同じ見出しの行）を指しているときだけ、重ねて出さない。
 * 重いほうを残す（同じなら名前つき。ただし復元できない部分がある鍵は、その補足を出せる秘密鍵の項目を残す）。
 * ファイル名・変数名があるだけでは、秘密鍵の項目を消さない。
 */
function keyDuplicates(scan: ScanResult): { keys: Set<PrivateKeyLocation>; named: Set<SecretNameLocation> } {
  const keys = new Set<PrivateKeyLocation>();
  const named = new Set<SecretNameLocation>();
  for (const h of scan.secretNames) {
    if (h.keyLine === undefined || !h.value) continue;
    const k = scan.privateKeys.find((p) => !p.publicDir && p.file === h.file && p.line === h.keyLine);
    if (!k || keys.has(k)) continue;
    const diff = RISK_RANK[secretRisk(h)] - RISK_RANK[privateKeyRisk(k)];
    if (diff > 0 || (diff === 0 && !k.unresolved)) keys.add(k);
    else named.add(h);
  }
  return { keys, named };
}

function keyLocationText(k: PrivateKeyLocation): string {
  return `${k.file}:${k.line}（${KEY_KIND_LABEL[k.kind]}${keyStateText(k)}・${GIT_LABEL[k.git]}）`;
}

function privateKeyChecks(scan: ScanResult): CheckItem[] {
  const items: CheckItem[] = [];
  // 名前つきの秘密情報で、同じ鍵を同じ重さ以上で出している場所だけは重ねて出さない
  const duplicates = keyDuplicates(scan).keys;
  const keys = scan.privateKeys.filter((k) => !k.publicDir && !duplicates.has(k));
  const danger = keys.filter((k) => privateKeyRisk(k) === 'danger');
  const warn = keys.filter((k) => privateKeyRisk(k) === 'warn');
  const ignored = keys.filter((k) => k.value !== 'test-like' && privateKeyRisk(k) === 'info');
  const fakes = keys.filter((k) => k.value === 'test-like');
  const details: NonNullable<CheckItem['details']> = [];
  if (ignored.length) details.push({ summary: `Git の対象外（.gitignore）の秘密鍵 ${ignored.length}件（公開の問題としては数えていません）`, items: ignored.map((k) => `${k.file}:${k.line}`) });
  if (fakes.length) details.push({ summary: `ダミー（見本の文字・同じ値の繰り返し）と判断した鍵 ${fakes.length}件`, items: fakes.map((k) => `${k.file}:${k.line}`) });
  if (danger.length > 0) {
    items.push({
      id: 'private-key-danger',
      tech: 'credentials',
      status: 'danger',
      title: `秘密鍵が${danger.length}か所にあり、Git で公開されるおそれがあります`,
      body:
        'ファイルの中身から、秘密鍵（サーバーやサービスに、あなたとして接続するための鍵）だと確認できました。Git で管理されているか、.gitignore で除外されていないため、GitHub などに公開すると鍵も一緒に公開されます。' +
        'ファイルをフォルダの外（または .gitignore で除外した場所）に移してください。すでにコミット・公開してしまった場合は、鍵を発行したサービス（Google Cloud・Firebase・サーバーなど）で鍵を無効化・削除し、作り直してください。鍵の中身はこの画面に表示していません。',
      points: danger.map(keyLocationText),
    });
  }
  if (warn.length > 0) {
    items.push({
      id: 'private-key-warn',
      tech: 'credentials',
      status: 'warn',
      title: `秘密鍵が${warn.length}か所にあります。公開されないか確認してください`,
      body:
        'ファイルの中身から、秘密鍵の形だと分かりました。Git で管理していないフォルダにある鍵、パスフレーズで暗号化された鍵、または秘密鍵の形だが本物かどうかを確認できなかった鍵です（確認できない鍵も、安全とは扱っていません）。' +
        '共有フォルダ・クラウドの同期フォルダ・公開するファイルに含まれないかを確認し、必要なら .gitignore に追加してください。鍵の中身はこの画面に表示していません。',
      points: warn.map(keyLocationText),
      ...(details.length ? { details } : {}),
    });
  } else if (details.length > 0) {
    items.push({
      id: 'private-key-info',
      tech: 'credentials',
      status: 'ok',
      title: '秘密鍵：Git の対象外の鍵・テスト用の鍵は、問題として数えていません',
      body: '.gitignore で除外された秘密鍵は、Git で公開されないため問題として数えていません（公開フォルダの中にある場合は別に知らせます）。証明書・公開鍵は秘密鍵ではないので数えません。鍵の中身はこの画面に表示していません。',
      details,
    });
  }
  return items;
}

// ───────────── 公開フォルダ ─────────────

const EXPOSURE_LABEL: Record<PublicExposure['kind'], string> = {
  env: '.env ファイル（設定の値が入っている）',
  'db-backup': 'データベースのファイル・バックアップ',
  'db-sql': 'データ入りの SQL ファイル（見本のデータの可能性あり）',
  'credential-json': 'OAuth クライアントの秘密（client_secret）入りの JSON',
};

function publicFolderChecks(scan: ScanResult): CheckItem[] {
  const keys = scan.privateKeys.filter((k) => k.publicDir && k.value !== 'test-like');
  const danger = [
    ...scan.publicExposures.filter((x) => x.kind !== 'db-sql').map((x) => `${x.file}（${EXPOSURE_LABEL[x.kind]}・公開フォルダ ${x.publicDir}/ の中）`),
    ...keys.filter((k) => privateKeyRisk(k) === 'danger').map((k) => `${k.file}:${k.line}（${KEY_KIND_LABEL[k.kind]}・公開フォルダ ${k.publicDir}/ の中）`),
  ];
  const warn = [
    ...scan.publicExposures.filter((x) => x.kind === 'db-sql').map((x) => `${x.file}（${EXPOSURE_LABEL[x.kind]}・公開フォルダ ${x.publicDir}/ の中）`),
    ...keys.filter((k) => privateKeyRisk(k) === 'warn').map((k) => `${k.file}:${k.line}（${KEY_KIND_LABEL[k.kind]}${keyStateText(k)}・公開フォルダ ${k.publicDir}/ の中）`),
  ];
  const items: CheckItem[] = [];
  const common =
    'public/ や static/ などの公開フォルダの中身は、ビルドのときにそのまま Web に公開され、URL を知っていれば誰でもダウンロードできます。' +
    '.gitignore で Git の対象外にしていても、ビルド・デプロイには含まれることがあります。';
  if (danger.length > 0) {
    items.push({
      id: 'public-folder-danger',
      tech: 'credentials',
      status: 'danger',
      title: `公開フォルダに、公開してはいけないファイルが${danger.length}件あります`,
      body:
        common +
        'ファイルを公開フォルダの外に移してください。すでに公開してしまった場合は、中の鍵・パスワードを作り直し、データベースのデータが読まれた可能性を確認してください。ファイルの中身はこの画面に表示していません。',
      points: danger,
    });
  }
  if (warn.length > 0) {
    items.push({
      id: 'public-folder-warn',
      tech: 'credentials',
      status: 'warn',
      title: `公開フォルダに、確認が必要なファイルが${warn.length}件あります`,
      body: common + '見本のデータなど、公開してよい内容かを確認してください。ファイルの中身はこの画面に表示していません。',
      points: warn,
    });
  }
  return items;
}

// ───────────── Git の履歴 ─────────────

const PUSHED_LABEL: Record<HistoryFinding['pushed'], string> = {
  yes: 'push 済み',
  no: 'まだ push していない',
  'no-remote': 'リモートなし',
  unknown: 'push 済みか確認できなかった',
};

/** 履歴に残った秘密情報の重大度。push 済みの本物らしい値 → 🔴。それ以外（まだ push していない・判断できない値・暗号化された鍵）→ 🟠 */
export function historyRisk(f: HistoryFinding): 'danger' | 'warn' {
  if (f.value !== 'real-like' || f.encrypted) return 'warn';
  return f.pushed === 'yes' ? 'danger' : 'warn';
}

function historyLabel(f: HistoryFinding): string {
  if (f.kind === 'private-key') return f.keyKind ? KEY_KIND_LABEL[f.keyKind] : '秘密鍵';
  return SECRET_DEFINITIONS.find((d) => d.id === f.defId)?.label ?? '秘密情報';
}

function historyText(f: HistoryFinding): string {
  const when = f.commit ? `コミット ${f.commit}${f.date ? `（${f.date}）` : ''}で追加` : 'コミットは特定できなかった';
  const value = f.value === 'uncertain' ? '・本物か判断できない値' : f.encrypted ? '・パスフレーズで暗号化されている' : '';
  const others = f.occurrences > 1 ? `・同じ値がほかに ${f.occurrences - 1} か所${f.otherFiles.length ? `（${f.otherFiles.join('、')}）` : ''}` : '';
  return `${historyLabel(f)}：${f.file}（${when}・${PUSHED_LABEL[f.pushed]}${value}${others}）`;
}

const HISTORY_NOTE = 'このツールは履歴を書き換えません。値はこの画面に表示していません。';

function gitHistoryChecks(scan: ScanResult): CheckItem[] {
  const h = scan.gitHistory;
  const truncatedNote = h.truncated ? '履歴が大きいため、上限（ファイルの版の数・容量・時間）の範囲で一部だけを確認しました。' : '';
  if (h.status === 'no-git-command') {
    return [
      {
        id: 'git-history-skipped',
        tech: 'credentials',
        status: 'manual',
        title: 'Git の履歴はチェックしていません（このPCで Git が見つかりませんでした）',
        body:
          'このフォルダは Git で管理されていますが、git コマンドが見つからなかったため、過去のコミットに秘密情報が残っていないかは確認していません（ほかのチェックは通常どおり行っています）。' +
          'Git for Windows などを入れると確認できます。',
      },
    ];
  }
  if (h.status === 'failed') {
    const why =
      h.reason === 'partial-clone'
        ? '一部だけを取得したリポジトリ（partial clone）のため、履歴を読むと Git がリモートからファイルを取りに行く（通信する）おそれがあります。このツールは通信しないよう、履歴を読みませんでした。'
        : h.reason === 'dubious-ownership'
        ? 'Git の安全のための設定（フォルダの持ち主がいまのユーザーと違う）により、履歴を読めませんでした。'
        : h.reason === 'timeout'
          ? '履歴が大きく、時間内に読み終えられませんでした。'
          : '履歴を読み取れませんでした。';
    return [
      {
        id: 'git-history-skipped',
        tech: 'credentials',
        status: 'manual',
        title: 'Git の履歴はチェックできませんでした',
        body: `${why}過去のコミットに秘密情報が残っていないかは確認していません（ほかのチェックは通常どおり行っています）。`,
      },
    ];
  }
  if (h.status !== 'checked') return [];
  const items: CheckItem[] = [];
  const danger = h.findings.filter((f) => historyRisk(f) === 'danger');
  const warn = h.findings.filter((f) => historyRisk(f) === 'warn');
  if (danger.length > 0) {
    items.push({
      id: 'git-history-danger',
      tech: 'credentials',
      status: 'danger',
      title: `Git の履歴（push 済み）に、秘密情報が${danger.length}件残っています`,
      body:
        'いまのファイルからは消えていても、過去のコミットに残っています。push 済みの履歴は、そのリポジトリを見られる人なら過去のコミットから取り出せます（公開リポジトリなら誰でも）。' +
        'ファイルから消すだけでは不十分です。まず各サービスで、そのキー・鍵を無効にして作り直してください（作り直せば、履歴に残った古い値は使えなくなります）。' +
        '履歴から取り除くには git filter-repo などで履歴を書き換える必要があり、共同作業者への連絡も必要です。' +
        truncatedNote +
        HISTORY_NOTE,
      points: danger.map(historyText),
    });
  }
  if (warn.length > 0) {
    items.push({
      id: 'git-history-warn',
      tech: 'credentials',
      status: 'warn',
      title: `Git の履歴に、秘密情報が${warn.length}件残っています（まだ公開されていない可能性があります）`,
      body:
        'いまのファイルからは消えていても、過去のコミットに残っています。まだ push していない・リモートがない履歴なら、push すると一緒に公開されます。' +
        'push する前にキー・鍵を作り直すか、コミットをやり直して履歴から取り除いてください。本物か判断できない値・パスフレーズで暗号化された鍵もここに含めています。' +
        truncatedNote +
        HISTORY_NOTE,
      points: warn.map(historyText),
    });
  }
  if (items.length === 0 && h.stats.commits > 0) {
    items.push({
      id: 'git-history-ok',
      tech: 'credentials',
      status: 'ok',
      title: 'Git の履歴に、秘密情報は見つかりませんでした',
      body:
        `過去のコミット ${h.stats.commits} 件に含まれる、設定ファイル・ソースコード・.env・鍵ファイルの版 ${h.stats.blobs} 件を確認しました。` +
        'いまのファイルにもある値は、上の項目で知らせています。' +
        truncatedNote +
        HISTORY_NOTE,
    });
  }
  return items;
}

// ───────────── Firebase のセキュリティルール ─────────────

const RULES_FILE_LABEL = { firestore: 'Cloud Firestore', storage: 'Cloud Storage', database: 'Realtime Database' } as const;
const ACCESS_LABEL: Record<RuleFinding['access'], string> = { read: '読み取り', write: '書き込み', 'read-write': '読み取り・書き込み' };

function ruleText(f: RuleFinding & { file: string }): string {
  const scope = f.scope === 'all' ? 'すべてのデータ' : `${f.path} のデータ`;
  const what: Record<RuleFinding['reason'], string> = {
    open: `誰でも${scope}の${ACCESS_LABEL[f.access]}ができる`,
    'test-mode-active': `期限付きのテストモード：期限まで誰でも${scope}の${ACCESS_LABEL[f.access]}ができる`,
    'test-mode-expired': 'テストモードのルールのまま（期限切れのため、いまはこのルールでは拒否される）',
    'auth-only': `ログインしていれば誰でも${scope}の${ACCESS_LABEL[f.access]}ができる`,
  };
  return `${f.file}:${f.line}（${what[f.reason]}）`;
}

const RULES_NOTE = 'このPC内のルールファイルを確認した結果です。現在公開中の設定そのものとは限りません（Firebase コンソールで、実際にデプロイされているルールも確認してください）。';

function firebaseRulesChecks(scan: ScanResult): CheckItem[] {
  const { files, findings } = scan.firebaseRules;
  const link = { href: 'https://firebase.google.com/docs/rules/insecure-rules', label: 'Firebase 公式：安全でないルールの例' };
  if (files.length === 0) {
    return [
      {
        id: 'firebase-rules',
        tech: 'firebase',
        status: 'manual',
        title: 'Firebase のセキュリティルールを確認してください（ルールファイルが見つかりませんでした）',
        body:
          'Firebase では「セキュリティルール」で、誰がどのデータを読み書きできるかを決めます。' +
          'このフォルダにはルールファイル（firestore.rules・storage.rules・database.rules.json）が見つからなかったため、自動では確認していません。' +
          'テスト用の「誰でも読み書きできる」ルールのまま公開すると、データを読まれたり消されたりする可能性があります。Firebase コンソールでルールを確認してください。',
        link: { href: 'https://firebase.google.com/docs/rules', label: 'Firebase 公式：セキュリティルール' },
      },
    ];
  }
  const items: CheckItem[] = [];
  const danger = findings.filter((f) => f.severity === 'danger');
  const warn = findings.filter((f) => f.severity === 'warn');
  if (danger.length > 0) {
    items.push({
      id: 'firebase-rules-danger',
      tech: 'firebase',
      status: 'danger',
      title: `Firebase のルールで、誰でもデータを読み書きできる設定が${danger.length}か所あります`,
      body:
        'ルールで「誰でも許可」（if true・条件なしの allow・true）や、期限前のテストモードになっている場所があります。' +
        'このまま公開すると、アプリを使っていない人でも、データを読んだり、書き換えたり、消したりできてしまいます。' +
        'ログインしている本人のデータだけを読み書きできるルールなどに直してから公開してください。' +
        RULES_NOTE,
      points: danger.map(ruleText),
      link,
    });
  }
  if (warn.length > 0) {
    items.push({
      id: 'firebase-rules-warn',
      tech: 'firebase',
      status: 'warn',
      title: `Firebase のルールで、確認が必要な設定が${warn.length}か所あります`,
      body:
        '一部のデータを誰でも読める設定、ログインしていれば誰でも全体を読み書きできる設定、または期限切れのテストモードのルールがあります。' +
        '公開してよいデータか、ほかの利用者のデータまで読み書きできてしまわないかを確認してください。' +
        RULES_NOTE,
      points: warn.map(ruleText),
      link,
    });
  }
  const unparsed = files.filter((f) => !f.parsed);
  if (danger.length === 0 && warn.length === 0) {
    items.push({
      id: 'firebase-rules-checked',
      tech: 'firebase',
      status: 'ok',
      title: 'Firebase のルールファイルに、誰でも読み書きできる決まった形は見つかりませんでした',
      body:
        '「誰でも許可」「期限付きのテストモード」「ログインしていれば誰でも全体」の、よくある危険な形だけを確認しました。それ以外の複雑なルールが正しいかは判定していません（危険とも安全とも判断していません）。' +
        RULES_NOTE,
      points: files.filter((f) => f.parsed).map((f) => `${f.file}（${RULES_FILE_LABEL[f.kind]}）`),
      link,
    });
  }
  if (unparsed.length > 0) {
    items.push({
      id: 'firebase-rules-unparsed',
      tech: 'firebase',
      status: 'manual',
      title: 'Firebase のルールファイルの一部を読み取れませんでした（判定していません）',
      body: 'ファイルの形式を読み取れなかったため、危険かどうかを判定していません。Firebase コンソールでルールを確認してください。' + RULES_NOTE,
      points: unparsed.map((f) => `${f.file}（${RULES_FILE_LABEL[f.kind]}）`),
      link,
    });
  }
  return items;
}

/**
 * 秘密情報：危険・要確認の場所だけを、サービスごとに件数つきで出す。
 * 参照だけ・テスト用・公開してよいキーなどは、1つのカードの折りたたみにまとめる（「ファイル名:行番号」だけ）。
 */
function secretChecks(scan: ScanResult): CheckItem[] {
  const items: CheckItem[] = [];
  const details: NonNullable<CheckItem['details']> = [];
  const duplicates = keyDuplicates(scan).named;
  for (const def of SECRET_DEFINITIONS) {
    const hits = scan.secretNames.filter((h) => h.defId === def.id && !duplicates.has(h));
    if (hits.length === 0) continue;
    const danger = hits.filter((h) => secretRisk(h) === 'danger');
    const warn = hits.filter((h) => secretRisk(h) === 'warn');
    const info = hits.filter((h) => secretRisk(h) === 'info');

    if (danger.length > 0) {
      items.push({
        id: `secret-${def.id}-danger`,
        tech: 'credentials',
        status: 'danger',
        title: `${def.label}が${danger.length}か所に直接書かれている可能性があります`,
        body:
          `${def.description}本物の形式に見える値が、Git で公開される・アプリと一緒に配布されるおそれのある場所に書かれています。` +
          `値をそのファイルから消し、.env（Git の対象外）や、GitHub Actions のシークレットなど公開されない場所に移してください。すでにコミット・公開してしまった場合は、${def.remediation}値はこの画面に表示していません。`,
        points: danger.map(locationText),
      });
    }
    if (warn.length > 0) {
      items.push({
        id: `secret-${def.id}-warn`,
        tech: 'credentials',
        status: 'warn',
        title: `${def.label}が${warn.length}か所に書かれています。公開されないか確認してください`,
        body:
          `${def.description}` +
          (warn.some((h) => h.value?.kind === 'uncertain')
            ? 'ローカル開発用の鍵の形をした値がありますが、ローカル用だと確認できなかったため、安全とは扱わずに要確認としています（本番の鍵でないか確認してください）。'
            : '') +
          (warn.some((h) => h.value?.kind === 'real-like')
            ? '本物の形式に見える値が、Git の対象外のファイル・Git で管理していないフォルダ・.gitignore で除外していない .env のどれかに書かれています。'
            : '') +
          '.gitignore に入っているか、共有フォルダやクラウドの同期フォルダに入っていないかを、公開の前に確認してください。できれば .env（Git の対象外）にまとめてください。値はこの画面に表示していません。',
        points: warn.map(locationText),
      });
    }
    // 折りたたみ（ファイル名:行番号だけ）
    const where = (h: SecretNameLocation) => `${h.file}:${h.line}`;
    const refs = info.filter((h) => !h.value);
    const fakes = info.filter((h) => h.value && (h.value.kind === 'test-like' || h.value.kind === 'placeholder'));
    const publics = info.filter((h) => h.value?.kind === 'public');
    const localEnv = info.filter((h) => h.value?.kind === 'real-like');
    if (refs.length) details.push({ summary: `${def.label}：参照している場所 ${refs.length}件（値は書かれていない）`, items: refs.map(where) });
    if (fakes.length) details.push({ summary: `${def.label}：テスト用・ダミーの値と判断した場所 ${fakes.length}件`, items: fakes.map(where) });
    if (publics.length) details.push({ summary: `${def.label}の欄にある、公開してよいキー ${publics.length}件`, items: publics.map(where) });
    if (localEnv.length) details.push({ summary: `${def.label}：.env（Git の対象外）に値がある場所 ${localEnv.length}件`, items: localEnv.map(where) });
  }
  if (details.length > 0) {
    items.push({
      id: 'secrets-info',
      tech: 'credentials',
      status: 'ok',
      title: '認証情報：参照・テスト用の値・公開してよいキーは、問題として数えていません',
      body:
        '環境変数やシークレットを参照しているだけの場所、テスト用・ダミーの値、公開してよいキー（Supabase の publishable キー・anon キーなど）、Git の対象外の .env は、漏れの根拠にしていません。' +
        'テスト用と判断した値が本物でないかは、念のためご自身でも確認してください。値はこの画面に表示していません。',
      details,
    });
  }
  return items;
}

export function buildChecks(scan: ScanResult): CheckItem[] {
  const items: CheckItem[] = [];

  // ── Supabase：既存の Security Advisor 診断へ案内 ──
  if (has(scan, 'supabase')) {
    items.push({
      id: 'supabase-advisor',
      tech: 'supabase',
      status: 'action',
      title: 'Supabase のデータベース設定を確認する',
      body:
        'Supabase を使っているようです。データベースの「誰がどのデータを読めるか」の設定に問題がないかを、Supabase 公式の診断（Security Advisor）で確認できます。' +
        'データベースの中身は読まず、設定の診断結果だけを取得します。',
      supabase: { refs: scan.supabaseRefs },
    });
  }

  // ── 公開される変数に秘密の値 ──
  // 秘密情報の定義で扱った変数は、ここでは重ねて出さない
  const handled = new Set(scan.secretNames.filter((h) => h.as).map((h) => `${h.file}\0${h.as}`));
  const exposed = scan.envFiles
    .flatMap((f) => f.publicSecretKeys.map((k) => ({ file: f.path, ...k })))
    .filter((k) => !handled.has(`${k.file}\0${k.name}`));
  const exposedValues = exposed.filter((k) => k.reason !== 'name');
  if (exposedValues.length > 0) {
    items.push({
      id: 'env-public-secret-value',
      tech: 'env',
      status: 'danger',
      title: 'アプリに埋め込まれる変数に、秘密のキーが入っている可能性があります',
      body:
        'NEXT_PUBLIC_ や EXPO_PUBLIC_ などで始まる変数は、公開したアプリの中に埋め込まれ、誰でも取り出せます。' +
        'そこに秘密のキーが入っていると、他人がそのキーを使ってデータを読み書きしたり、あなたの料金で外部サービスを使ったりできてしまいます。' +
        '値はこの画面に表示していません。',
      points: exposedValues.map((k) => `${k.file} の ${k.name}（${REASON_LABEL[k.reason] ?? k.reason}）`),
    });
  }
  const exposedNames = exposed.filter((k) => k.reason === 'name');
  if (exposedNames.length > 0) {
    items.push({
      id: 'env-public-secret-name',
      tech: 'env',
      status: 'warn',
      title: '公開される変数に、秘密情報らしい名前のものがあります',
      body:
        'NEXT_PUBLIC_ や EXPO_PUBLIC_ などで始まる変数は、公開したアプリの中に埋め込まれ、誰でも見られます。' +
        '名前に SECRET や SERVICE_ROLE などが入っている変数が含まれています。中身が本当に公開してよいものか確認してください。',
      points: exposedNames.map((k) => `${k.file} の ${k.name}`),
    });
  }

  // ── 秘密情報（サービスごとの定義：secret-defs.ts） ──
  items.push(...secretChecks(scan));

  // ── 秘密鍵・サービスアカウント鍵、公開フォルダ ──
  items.push(...privateKeyChecks(scan));
  items.push(...publicFolderChecks(scan));

  // ── Git の履歴に残った秘密情報 ──
  items.push(...gitHistoryChecks(scan));

  // ── .env が Git に入ってしまわないか ──
  const realEnv = scan.envFiles.filter((f) => !f.isExample);
  const notIgnored = realEnv.filter((f) => f.git === 'not-ignored');
  if (notIgnored.length > 0) {
    items.push({
      id: 'env-not-gitignored',
      tech: 'env',
      status: 'warn',
      title: '.env ファイルが Git の管理対象から外れていません',
      body:
        '.env ファイルには APIキーなどが書かれます。.gitignore に書いておかないと、GitHub などに公開したときにキーも一緒に公開されてしまうことがあります。' +
        '.gitignore に「.env*」を追加し、すでにコミットしてしまった場合はキーを作り直してください。',
      points: notIgnored.map((f) => f.path),
    });
  } else if (realEnv.length > 0 && realEnv.every((f) => f.git === 'ignored')) {
    items.push({
      id: 'env-gitignored',
      tech: 'env',
      status: 'ok',
      title: '.env ファイルは Git の管理対象から外れています',
      body: '.gitignore で .env ファイルが除外されていました。過去にコミットしたことがある場合は、履歴に残っていないかも確認してください。',
      points: realEnv.map((f) => f.path),
    });
  } else if (realEnv.some((f) => f.git === 'no-git')) {
    items.push({
      id: 'env-no-git',
      tech: 'env',
      status: 'manual',
      title: '.env ファイルを公開しないよう注意してください',
      body: 'このフォルダは Git で管理されていないようです。GitHub などに公開する前に、.gitignore に「.env*」を追加してください。',
      points: realEnv.map((f) => f.path),
    });
  }

  // ── Firebase：このPCの中のルールファイル ──
  if (has(scan, 'firebase')) items.push(...firebaseRulesChecks(scan));

  // ── スマホアプリ・Webアプリに埋め込むキー ──
  if (has(scan, 'expo') || has(scan, 'react-native')) {
    items.push({
      id: 'mobile-embedded-keys',
      tech: has(scan, 'expo') ? 'expo' : 'react-native',
      status: 'manual',
      title: 'スマホアプリに入れたキーは、誰でも取り出せます',
      body:
        'アプリの中に書いたキー（EXPO_PUBLIC_ で始まる変数を含む）は、公開したアプリから取り出すことができます。' +
        'AIや決済などの秘密のキーはアプリに入れず、サーバー側（Supabase の Edge Functions など）で使ってください。',
      link: { href: 'https://docs.expo.dev/guides/environment-variables/', label: 'Expo 公式：環境変数' },
    });
  }
  if (has(scan, 'nextjs')) {
    items.push({
      id: 'nextjs-public-env',
      tech: 'nextjs',
      status: 'manual',
      title: 'NEXT_PUBLIC_ で始まる変数は、ブラウザから見えます',
      body:
        'Next.js では、NEXT_PUBLIC_ で始まる変数はブラウザに送られ、誰でも見られます。秘密のキーは NEXT_PUBLIC_ を付けずに、サーバー側の処理だけで使ってください。',
      link: { href: 'https://nextjs.org/docs/app/guides/environment-variables', label: 'Next.js 公式：環境変数' },
    });
  }

  // ── 外部API ──
  // 一般的な API キーが見つかった場合だけ（CLAUDE_CODE_OAUTH_TOKEN など専用の案内があるものは、ここには入れない）
  if (scan.externalApis.length > 0) {
    items.push({
      id: 'external-api-keys',
      tech: 'external-api',
      status: 'manual',
      title: '外部サービスのキーは、サーバー側だけで使ってください',
      body:
        '外部サービスのキーが漏れると、他人にあなたの料金で使われることがあります。' +
        'キーはアプリやブラウザに入れず、サーバー側だけで使い、各サービスの管理画面で利用上限を設定しておくと安心です。',
      points: scan.externalApis.map((a) => `${a.name}（${a.via}）`),
    });
  }

  // 🔴・🟠 の項目に、直し方と AI への修正依頼文を付ける
  return items.map((item) => attachGuide(item, scan.root));
}
