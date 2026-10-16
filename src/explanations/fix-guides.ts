// フォルダのチェック結果（🔴・🟠）ごとの「直し方」と、AIへの修正依頼文。
// 外部のAI APIは使わない。すべて固定の文面から組み立てる。
//
// 方針:
// ・初心者が上から順に進められる手順（3〜5ステップ）にする。
// ・秘密情報が漏れた可能性がある場合は、コードから消すだけで解決した扱いにしない。
//   キー・鍵の無効化と作り直しを先に案内する（作り直すまで、古い値は使えてしまう）。
// ・本物か判断できない値・公開してよいか利用者が決める項目は、「あなたの判断が必要」と分けて示す。
// ・AIへの依頼文に入れるのは、ファイル名・行番号・変数名・指摘の種類だけ。値・絶対パス・ユーザー名は入れない。
// ・キーの無効化・再発行、Git の履歴の書き換え、ルールのデプロイは、AIにさせず利用者が行う操作として書く。

import type { CheckItem } from '../checks/build.js';
import { SECRET_DEFINITIONS, type SecretDefinition } from '../detect/secret-defs.js';
import { composeFixPrompt } from './prompt.js';
import { sanitizeForPrompt } from './template.js';

export interface FixGuide {
  /** 利用者が上から順に行う手順 */
  steps: string[];
  /** 自動では判断しきれず、利用者の判断が必要なこと（誤検出・未確認など） */
  judgement?: string;
  /** AIに貼り付ける修正依頼文 */
  aiPrompt: string;
}

interface GuideSpec {
  steps: string[];
  judgement?: string;
  ai: {
    task: string;
    extraChecks?: string[];
    extraRules?: string[];
    ownerActions?: string[];
  };
}

export const RECHECK_STEP = '直したら、画面の「修正したら、もう一度チェックする」を押して、この項目が消えたか確認します。';

/** サービスごとの作り直し方（かっこの中に入れるので、文末の「。」は外す） */
const remedy = (def: SecretDefinition) => def.remediation.replace(/。+$/, '');

function secretDangerGuide(def: SecretDefinition): GuideSpec {
  return {
    judgement: 'テスト用の値で、本物のキーではないと確かな場合は、対応は不要です（迷ったら作り直してください）。',
    steps: [
      `すでにコミット・push した、またはアプリを公開したことがあるなら、最初に ${def.service} の管理画面で、そのキーを無効にして作り直します（${remedy(def)}）。コードから消すだけでは、古いキーは使えるままです。`,
      '新しいキーは .env（Git の対象外）や、ホスティング先（Vercel など）の環境変数の設定に入れます。キーの値をコードやチャットに貼り付けないでください。',
      'コードからキーの値を消し、環境変数から読む形に直します（下の「AIに修正を頼む」も使えます）。秘密のキーは NEXT_PUBLIC_ や EXPO_PUBLIC_ で始まる変数に入れず、サーバー側だけで使います。',
      RECHECK_STEP,
    ],
    ai: {
      task: `次の場所に書かれている ${def.label} の値をコードや設定ファイルから取り除き、環境変数（サーバー側だけで読むもの）から読み込む形に直してください。`,
      extraChecks: ['そのキーをコードのどこで使っているか（ブラウザ・スマホアプリ側か、サーバー側か）', '.gitignore で .env などが除外されているか'],
      extraRules: [
        '新しいキーの値を、あなたがファイルに書き込まないこと（変数名と読み込む処理だけを用意し、値は私が入れる）。',
        'NEXT_PUBLIC_ や EXPO_PUBLIC_ など、アプリに埋め込まれて公開される変数にしないこと。',
      ],
      ownerActions: [`${def.service} の管理画面での、キーの無効化と作り直し（${remedy(def)}）`, '新しいキーの値を .env やホスティング先の環境変数に入れること'],
    },
  };
}

function secretWarnGuide(def: SecretDefinition): GuideSpec {
  return {
    judgement: '本物のキーかどうか、または公開される場所かどうかを、このツールでは判断しきれませんでした。あなたの判断が必要です。',
    steps: [
      '一覧の場所の値が、いま使っている本物のキーかを確認します（テスト用・使っていないキーなら、対応は不要です）。',
      'そのファイルが GitHub などに公開されないか（.gitignore で除外されているか）、共有フォルダやクラウドの同期フォルダに入っていないかを確認します。',
      `本物のキーで、公開されるおそれがあるなら、値を .env（Git の対象外）へ移します。すでに公開した可能性があれば、${def.service} の管理画面でキーを作り直します（${remedy(def)}）。`,
      RECHECK_STEP,
    ],
    ai: {
      task: `次の場所にある ${def.label} について、Git で公開されるおそれがないか（.gitignore・Git での管理状況）を調べて報告してください。公開されるおそれがある場合は、値をコードや設定ファイルから取り除き、.env などの環境変数から読む形に直してください。本物のキーかどうかの判断は私が行います。`,
      extraRules: ['新しいキーの値を、あなたがファイルに書き込まないこと（値は私が入れる）。'],
      ownerActions: ['本物のキーかどうかの判断', `必要な場合の、${def.service} の管理画面でのキーの作り直し（${remedy(def)}）`],
    },
  };
}

const FIXED_GUIDES: Record<string, GuideSpec> = {
  'env-public-secret-value': {
    steps: [
      '最初に、その変数に入っているキーを発行したサービスの管理画面で、キーを無効にして作り直します。公開したアプリやサイトからは、誰でもこの値を取り出せる状態でした。',
      '新しいキーは、NEXT_PUBLIC_ や EXPO_PUBLIC_ を付けない変数名にして、.env（Git の対象外）やホスティング先の設定に入れます。',
      'キーを使う処理を、サーバー側（Next.js の API ルート・Supabase の Edge Functions など）へ移します（下の「AIに修正を頼む」も使えます）。',
      'アプリを作り直して（ビルドして）、公開し直します。',
      RECHECK_STEP,
    ],
    ai: {
      task: '次の変数は、ブラウザやスマホアプリに埋め込まれて公開される名前（NEXT_PUBLIC_ / EXPO_PUBLIC_ など）なのに、秘密のキーが入っている可能性があります。キーをサーバー側だけで使う形に直してください（公開される変数名をやめ、キーを使う処理をサーバー側へ移す）。',
      extraChecks: ['その変数をコードのどこで読んでいるか', 'サーバー側の処理を置ける場所（Next.js の API ルート・Supabase の Edge Functions など）があるか'],
      extraRules: ['新しいキーの値を、あなたがファイルに書き込まないこと（値は私が入れる）。'],
      ownerActions: ['キーを発行したサービスでの、キーの無効化と作り直し', '新しいキーの値を、公開されない変数として設定すること', 'アプリの再ビルドと公開'],
    },
  },
  'env-public-secret-name': {
    judgement: '名前から「秘密のキーらしい」と判断しただけで、値が秘密かどうかは確認していません。公開してよいキー（Supabase の anon・publishable キーなど）なら、対応は不要です。',
    steps: [
      'その変数に何のキーが入っているかを、キーを発行したサービスの説明で確認します。',
      '公開してはいけないキー（secret・service_role など）なら、キーを作り直し、NEXT_PUBLIC_ や EXPO_PUBLIC_ を付けない変数にして、サーバー側だけで使います。',
      '公開してよいキーなら、そのままで構いません。',
      RECHECK_STEP,
    ],
    ai: {
      task: '次の、アプリに埋め込まれて公開される変数について、何のキーが入る想定かをコードから調べて説明してください。秘密のキーであれば、サーバー側だけで使う形に直す案を出してください。変更は、私が内容を確認してから行ってください。',
      ownerActions: ['キーが公開してよいものかの判断', '必要な場合の、キーの作り直し'],
    },
  },
  'private-key-danger': {
    steps: [
      'すでにコミット・push したことがあるなら、最初に、鍵を発行したサービス（Google Cloud・Firebase・サーバーなど）で鍵を無効化・削除し、作り直します。',
      '鍵のファイルを、アプリのフォルダの外（または .gitignore で除外した場所）へ移します。',
      'コードが鍵のファイルを読んでいる場合は、移した場所や環境変数から読むように直します（下の「AIに修正を頼む」も使えます）。',
      '鍵のファイルが Git で管理されていたら、Git の管理から外します（git rm --cached。ファイル自体は消えません）。',
      RECHECK_STEP,
    ],
    ai: {
      task: '次の秘密鍵のファイルを、Git で公開されない構成に直してください（.gitignore への追加、Git の管理からの除外（git rm --cached）、鍵を読むコードの読み込み先の変更）。',
      extraChecks: ['その鍵のファイルを、コードのどこで読んでいるか'],
      extraRules: ['鍵のファイルの中身を開いたり、表示したりしないこと。', 'git rm --cached で Git の管理から外す場合も、ファイル自体は消さないこと。'],
      ownerActions: ['鍵を発行したサービスでの、鍵の無効化・削除と作り直し', '鍵のファイルの移動先を決めること'],
    },
  },
  'private-key-warn': {
    judgement: 'Git で管理していないフォルダにある鍵か、パスフレーズで暗号化された鍵です。公開されるかどうかは使い方によるため、あなたの判断が必要です。',
    steps: [
      '鍵のファイルが、共有フォルダ・クラウドの同期フォルダ・配布するファイルに含まれないかを確認します。',
      '使っていない鍵なら、アプリのフォルダの外へ移します。',
      'あとで Git を使う予定があれば、.gitignore に鍵のファイルを追加しておきます。',
      RECHECK_STEP,
    ],
    ai: {
      task: '次の秘密鍵のファイルが、公開されたり配布物に含まれたりするおそれがないかを調べて報告してください。必要なら、.gitignore への追加などの対策を提案してください。',
      extraRules: ['鍵のファイルの中身を開いたり、表示したりしないこと。', 'ファイルを消したり移したりしないこと（移すかどうかは私が決める）。'],
      ownerActions: ['鍵を移すかどうかの判断'],
    },
  },
  'public-folder-danger': {
    steps: [
      'すでにサイトやアプリを公開していたなら、最初に、そのファイルに入っている鍵・パスワードを作り直し、データベースのデータが読まれた可能性を確認します。',
      'ファイルを、公開フォルダ（public/・static/ など）の外へ移します。公開フォルダの中身は、ビルドのときにそのまま Web に公開されます。',
      'コードがそのファイルを読んでいる場合は、読み込み先を直します（下の「AIに修正を頼む」も使えます）。',
      'もう一度ビルドして公開し、そのファイルの URL を開けないことを確認します。',
      RECHECK_STEP,
    ],
    ai: {
      task: '次のファイルは、ビルドのときにそのまま Web に公開される公開フォルダ（public/・static/ など）に入っています。公開フォルダの外へ移す構成に直し、そのファイルを参照しているコードがあれば直してください。',
      extraChecks: ['そのファイルを、アプリのどこで使っているか（使っていないファイルか）'],
      extraRules: ['ファイルの中身（設定の値・データ）を開いたり、表示したりしないこと。'],
      ownerActions: ['公開済みだった場合の、鍵・パスワードの作り直しと、データが読まれていないかの確認', 'もう一度ビルドして公開すること'],
    },
  },
  'public-folder-warn': {
    judgement: '見本のデータの可能性があります。公開してよい内容かどうかは、あなたの判断が必要です。',
    steps: [
      'ファイルの中身に、本物の利用者のデータ・パスワード・個人情報が入っていないかを確認します。',
      '公開してはいけない内容なら、ファイルを公開フォルダの外へ移します。',
      '公開してよい見本のデータなら、そのままで構いません。',
      RECHECK_STEP,
    ],
    ai: {
      task: '次の、公開フォルダ（public/・static/ など）に入っているファイルについて、アプリのどこで使っているかを調べて報告してください。公開フォルダの外へ移す場合の変更案も出してください。変更は、私が内容を確認してから行ってください。',
      extraRules: ['ファイルの中身（データ）を表示しないこと。'],
      ownerActions: ['公開してよい内容かどうかの判断'],
    },
  },
  'git-history-danger': {
    judgement: 'キーを作り直したかどうかは、このツールでは確認できません。履歴に値が残っている限り、もう一度チェックしてもこの項目は表示されます。',
    steps: [
      '最初に、各サービスの管理画面で、そのキー・鍵を無効にして作り直します。push 済みの履歴は誰かに読まれた可能性があり、作り直せば古い値は使えなくなります。ファイルから消すだけでは解決しません。',
      '新しい値は .env（Git の対象外）などに入れ、コードやコミットに含めないようにします。',
      'いまのファイルに同じ値が残っていないか確認し、残っていれば取り除きます（下の「AIに修正を頼む」も使えます）。',
      '履歴からも取り除くかを決めます。履歴の書き換え（git filter-repo など）と強制 push が必要で、共同作業者への連絡も必要です。作り直したキーなら、書き換えなくても古い値は使えません。',
      RECHECK_STEP,
    ],
    ai: {
      task: 'Git の履歴（push 済み）に秘密情報が残っています。いまのファイル・コードに同じ値が残っていないかを確認し、残っていれば取り除いて、環境変数から読む形に直してください。.gitignore で .env などが除外されていることも確認してください。',
      extraRules: [
        'git filter-repo・rebase・force push などの、履歴の書き換えを実行しないこと（必要なら手順の案を説明するだけにする）。',
        '新しいキーの値を、あなたがファイルに書き込まないこと（値は私が入れる）。',
      ],
      ownerActions: ['各サービスの管理画面での、キー・鍵の無効化と作り直し（最初に行う）', '履歴を書き換えるかどうかの判断と、その実行'],
    },
  },
  'git-history-warn': {
    judgement: '本物か判断できない値・パスフレーズで暗号化された鍵も含まれます。テスト用の値だと確かな場合は、対応は不要です。',
    steps: [
      'まだ push していないなら、push する前に対処します。このまま push すると、この履歴も一緒に公開されます。',
      '本物のキーなら、各サービスの管理画面で作り直すのが一番確実です（作り直せば、古い値は使えなくなります）。',
      '作り直さない場合は、そのキーを含むコミットをやり直して、履歴から取り除きます。Git の操作に慣れていなければ、下の「AIに修正を頼む」で手順を説明してもらえます。',
      RECHECK_STEP,
    ],
    ai: {
      task: 'まだ push していない Git の履歴に、秘密情報が含まれています。push の前に履歴から取り除く方法（コミットのやり直し）を、このリポジトリの状況に合わせて手順として説明してください。',
      extraChecks: ['リモート（origin など）が設定されているか、どのコミットがまだ push されていないか'],
      extraRules: ['履歴の書き換え（rebase・reset・filter-repo・force push など）は、私が手順を確認するまで実行しないこと。'],
      ownerActions: ['本物のキーかどうかの判断と、必要な場合のキーの作り直し', '履歴のやり直しを実行するかどうかの判断'],
    },
  },
  'env-not-gitignored': {
    steps: [
      '.gitignore に「.env*」の行を追加します（見本の .env.example を Git に残したい場合は「!.env.example」も追加します）。',
      'すでに .env を Git に追加・コミットしていたら、Git の管理から外します（git rm --cached。ファイル自体は消えません）。',
      'コミットを push したことがあるなら、.env に入っているキーを、各サービスの管理画面で作り直します。',
      RECHECK_STEP,
    ],
    ai: {
      task: '.gitignore に .env ファイルを除外する設定を追加し、Git で管理されている .env があれば、Git の管理から外してください（git rm --cached）。',
      extraRules: ['.env ファイルの中身を開いたり、表示したりしないこと。', 'git rm --cached で Git の管理から外す場合も、ファイル自体は消さないこと。'],
      ownerActions: ['push したことがある場合の、キーの作り直し'],
    },
  },
  'firebase-rules-danger': {
    steps: [
      'Firebase コンソールで、実際に公開されているルールを確認します（このツールが確認したのは、このPC内のファイルです）。',
      'ルールを、「ログインしている本人のデータだけを読み書きできる」形など、アプリに必要な最小限の許可に直します（下の「AIに修正を頼む」も使えます）。',
      'Firebase のエミュレーターやコンソールのルールのシミュレーターで、他人のデータが読めないことを確認します。',
      '直したルールをデプロイします（例：firebase deploy --only firestore:rules）。',
      RECHECK_STEP,
    ],
    ai: {
      task: 'Firebase のセキュリティルールで、誰でも読み書きできる設定（if true・条件なしの allow・期限前のテストモードなど）になっている次の場所を、アプリに必要な最小限のアクセスだけを許すルールに直してください。',
      extraChecks: ['アプリの各画面が、どのデータを、誰として読む・書く必要があるか', 'Firebase Authentication を使っているか'],
      extraRules: ['直したルールを、私の確認なしにデプロイしないこと。', 'テストモード（期限付きで誰でも許可）に戻さないこと。'],
      ownerActions: ['直したルールの確認とデプロイ', 'Firebase コンソールで、公開中のルールが変わったことの確認'],
    },
  },
  'firebase-rules-warn': {
    judgement: 'お知らせなど、誰に見せてもよいデータなら、このままで構わない場合があります。あなたの判断が必要です。',
    steps: [
      '一覧の場所のデータを、誰に見せてよいか（全員・ログインした人・本人だけ）を決めます。',
      '「ログインしていれば誰でも全体を読み書きできる」設定は、本人のデータだけに絞ります。',
      '期限切れのテストモードのルールは、正式なルールに書き換えます。',
      '直したルールをデプロイし、画面の「修正したら、もう一度チェックする」で確認します。',
    ],
    ai: {
      task: 'Firebase のセキュリティルールの次の場所について、どのデータを誰が読み書きできる設定になっているかを説明し、アプリに必要な最小限の許可に直す案を出してください。変更は、私が内容を確認してから行ってください。',
      extraChecks: ['アプリの各画面が、どのデータを、誰として読む・書く必要があるか'],
      extraRules: ['直したルールを、私の確認なしにデプロイしないこと。'],
      ownerActions: ['どのデータを誰に見せてよいかの判断', '直したルールのデプロイ'],
    },
  },
};

const SECRET_ID = /^secret-(.+)-(danger|warn)$/;

/** 直し方の定義がある項目か（🔴・🟠 だけが対象） */
export function guideSpecFor(item: Pick<CheckItem, 'id' | 'status'>): GuideSpec | undefined {
  if (item.status !== 'danger' && item.status !== 'warn') return undefined;
  const m = SECRET_ID.exec(item.id);
  if (m) {
    const def = SECRET_DEFINITIONS.find((d) => d.id === m[1]);
    if (!def) return undefined;
    return m[2] === 'danger' ? secretDangerGuide(def) : secretWarnGuide(def);
  }
  return FIXED_GUIDES[item.id];
}

/** 直し方の定義がある、固定の項目ID（テストで、🔴・🟠 の項目に漏れがないことを確かめる） */
export const FIXED_GUIDE_IDS = Object.keys(FIXED_GUIDES);

// ───────────── 依頼文に、パソコン固有の場所を入れない ─────────────

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * 依頼文へ入れる文字列から、アプリのフォルダの絶対パスと、ユーザー名の入った絶対パスを取り除く。
 * チェック結果の場所はもともとアプリのフォルダからの相対パスだが、念のため二重に取り除く。
 */
export function redactLocalPaths(text: string, root: string): string {
  let out = text;
  // アプリのフォルダ（区切り文字の違い \ と / は同じ場所として扱う）
  if (root.length >= 3) {
    const pattern = root.split(/[\\/]+/).filter(Boolean).map(escapeRegExp).join('[\\\\/]+');
    const lead = /^[\\/]/.test(root) ? '[\\\\/]+' : '';
    out = out.replace(new RegExp(lead + pattern, 'gi'), '（アプリのフォルダ）');
  }
  // 絶対パスの先頭が、ドライブ名や区切り文字の直後の Users・home フォルダのものは、その次の名前（ユーザー名）まで伏せる。
  // 相対パスの途中にある home などのフォルダ名は、区切り文字の直前が英数字なので対象にしない
  out = out.replace(/(^|[\s（(「:：、,])(?:[A-Za-z]:[\\/]+|[\\/]+)(?:Users|home)[\\/]+[^\\/\s:：（）()「」、,]+/gi, '$1（ユーザーのフォルダ）');
  return out;
}

const PROMPT_RULES = [
  '秘密の値（キー・トークン・パスワード・秘密鍵の中身）を、画面・チャット・ログ・コミットメッセージに表示したり、書き写したりしないこと。',
  '推測だけで変更しないこと。判断できない場合は、変更する前に、分かったことと不明な点を私に説明して確認を取ること。',
  'Git の履歴の書き換え（rebase・reset・filter-repo・force push など）を、私の確認なしに行わないこと。',
  '既存の機能を壊さないこと。',
];

const PROMPT_CHECKS = ['下の「対象の場所」のファイルと、その周りのコードの使われ方'];

const PROMPT_FINAL = [
  '何を変更したか（変更したファイル）',
  'なぜその変更が必要だったか',
  '私が自分で行う必要が残っている操作（キーの作り直しなど）',
  '確認の方法（公開前チェック（koukai-check）でもう一度チェックし、この指摘が消えることを含む）',
];

const MAX_PROMPT_POINTS = 30;

/** チェック結果の1項目から、AIへの修正依頼文を作る（値・絶対パス・ユーザー名は入れない） */
export function buildFolderFixPrompt(item: Pick<CheckItem, 'title' | 'points'>, spec: GuideSpec, root: string): string {
  const clean = (text: string, max = 300) => sanitizeForPrompt(redactLocalPaths(text, root), max);
  const points = (item.points ?? []).slice(0, MAX_PROMPT_POINTS).map((p) => `- ${clean(p)}`);
  const more = (item.points?.length ?? 0) > MAX_PROMPT_POINTS ? [`- ほか ${(item.points?.length ?? 0) - MAX_PROMPT_POINTS} か所（公開前チェックの画面で確認できます）`] : [];
  const intro = [
    `アプリを公開する前のチェック（公開前チェック／koukai-check）で、次の指摘が出ました。`,
    `指摘：${clean(item.title, 200)}`,
  ];
  if (points.length > 0) intro.push('対象の場所（アプリのフォルダからの場所:行番号。値は書いていません）：', ...points, ...more);
  return composeFixPrompt({
    intro,
    task: spec.ai.task,
    checks: [...PROMPT_CHECKS, ...(spec.ai.extraChecks ?? [])],
    rules: [...PROMPT_RULES, ...(spec.ai.extraRules ?? [])],
    ownerActions: spec.ai.ownerActions,
    finalReport: PROMPT_FINAL,
  });
}

/** 🔴・🟠 の項目に、直し方と修正依頼文を付ける（それ以外の項目はそのまま） */
export function attachGuide(item: CheckItem, root: string): CheckItem {
  const spec = guideSpecFor(item);
  if (!spec) return item;
  const guide: FixGuide = { steps: spec.steps, aiPrompt: buildFolderFixPrompt(item, spec, root) };
  if (spec.judgement) guide.judgement = spec.judgement;
  return { ...item, guide };
}
