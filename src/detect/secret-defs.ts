// 秘密情報の定義（サービスごとのデータ）。共通の仕組み（secret-names.ts）がこのデータを読んで探す。
//
// 方針：
// ・名前に KEY / TOKEN / SECRET を含むだけで秘密とはしない。各サービスの公式資料で「秘密」と確認できたものだけを定義する。
// ・公開してよいキー（Supabase の publishable / anon など）は「公開可」として扱い、漏れとして数えない。
// ・形式が公式に書かれていないもの、判断があいまいなものは定義しない（docs/secret-definitions.md の表を参照）。

/** 値の形式の確かめ方 */
export type ValueCheck =
  /** 決まった接頭辞のトークン。random は接頭辞を除いた、ランダムなはずの部分 */
  | { type: 'token'; pattern: RegExp; minRandom: number }
  /** JWT。payload の role で秘密か公開可かを分ける（Supabase の service_role / anon） */
  | { type: 'jwt-role'; secretRoles: string[]; publicRoles: string[] }
  /** 形式が公表されていないキー。十分に長く、ランダムな文字列なら本物らしいとする（charset：使われる文字。省略時は英数字・_・-） */
  | { type: 'opaque'; minLength: number; maxLength?: number; charset?: RegExp }
  /** 接続先 URL に、ユーザー名とパスワードが入っているか */
  | { type: 'url-credentials' }
  /** PEM 形式の秘密鍵 */
  | { type: 'pem-private-key' };

export interface SecretDefinition {
  id: string;
  /** サービスの表示名 */
  service: string;
  /** 画面に出す名前（「〜が1か所に直接書かれている可能性があります」の主語） */
  label: string;
  /** この名前の環境変数に入っていれば、この秘密情報として調べる */
  envNames: string[];
  /** 環境変数ではない、設定ファイル・コードでの書き方（AWS の credentials ファイルの aws_secret_access_key・SDK の secretAccessKey など） */
  codeNames?: string[];
  /** 秘密値の形式（どれかに当てはまれば、この秘密情報の形） */
  checks: ValueCheck[];
  /** 名前がなくても、値の形だけで見つけてよい形式（接頭辞が公式に決まっていて、取り違えようがないものだけ） */
  shapeInText?: RegExp;
  /** 公開してよい、よく似たキー（漏れとして数えない） */
  publicLookalikes: { pattern: RegExp; label: string }[];
  /** 公開してよいキーを入れる環境変数名（漏れとして数えない。ただし秘密の値が入っていれば見つける） */
  publicEnvNames?: string[];
  /** 初心者向けの説明 */
  description: string;
  /** 漏れたときの対処 */
  remediation: string;
  /** 根拠にした公式資料 */
  source: string;
}

export const SECRET_DEFINITIONS: readonly SecretDefinition[] = [
  {
    id: 'claude-code-oauth',
    service: 'Claude Code',
    label: 'Claude Code の認証トークン',
    envNames: ['CLAUDE_CODE_OAUTH_TOKEN'],
    checks: [{ type: 'token', pattern: /^sk-ant-oat\d*-([A-Za-z0-9_-]+)$/, minRandom: 40 }],
    shapeInText: /sk-ant-oat\d{2}-[A-Za-z0-9_-]{20,}/g,
    publicLookalikes: [],
    description:
      'Claude Code を動かすための認証情報です（`claude setup-token` で作るもの）。公開されるコード・設定ファイル・公開用の環境変数（NEXT_PUBLIC_ などで始まるもの）には置かないでください。',
    remediation: 'トークンを作り直し（claude setup-token）、古いものは使えないようにしてください。',
    source: 'Claude Code（claude setup-token）',
  },
  {
    id: 'anthropic',
    service: 'Anthropic',
    label: 'Anthropic（Claude）の API キー',
    envNames: ['ANTHROPIC_API_KEY'],
    checks: [{ type: 'token', pattern: /^sk-ant-(?:api|admin)\d*-([A-Za-z0-9_-]+)$/, minRandom: 40 }],
    shapeInText: /sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}/g,
    publicLookalikes: [],
    description: 'Claude の API を、あなたのアカウントの料金で使うためのキーです。漏れると、他人に使われて料金が発生するおそれがあります。',
    remediation: 'Claude Console の Settings → API keys で新しいキーを作って差し替え、漏れたキーは削除してください。',
    source: 'Claude 公式ドキュメント「Get your Claude API key」（キーは sk-ant- で始まり、作成時に一度だけ表示。シークレットマネージャーなどに保管）',
  },
  {
    id: 'openai',
    service: 'OpenAI',
    label: 'OpenAI の API キー',
    envNames: ['OPENAI_API_KEY'],
    // 接頭辞の細かな種類（sk-proj- など）は公式資料で確かめられなかったため、名前と組み合わせたときだけ判定する（値の形だけでは探さない）
    checks: [{ type: 'token', pattern: /^sk-(?!ant-)(?:[a-z]+-)?([A-Za-z0-9_-]+)$/, minRandom: 32 }],
    publicLookalikes: [],
    description: 'OpenAI の API を、あなたのアカウントの料金で使うためのキーです。ブラウザやスマホアプリに入れると、誰でも取り出して使えてしまいます。',
    remediation: 'OpenAI の管理画面（API keys）で新しいキーを作って差し替え、漏れたキーは削除してください。',
    source: 'openai-node（公式 SDK）：ブラウザでの利用は既定で禁止（"it risks exposing your secret API credentials to attackers"）',
  },
  {
    id: 'elevenlabs',
    service: 'ElevenLabs',
    label: 'ElevenLabs の API キー',
    envNames: ['ELEVENLABS_API_KEY', 'ELEVEN_LABS_API_KEY', 'XI_API_KEY'],
    // キーの形式は公式資料に書かれていないため、名前と組み合わせ、十分に長くランダムな値のときだけ本物らしいとする
    checks: [{ type: 'opaque', minLength: 32 }],
    publicLookalikes: [],
    description: 'ElevenLabs の API を、あなたのアカウントの料金で使うためのキーです。公式に「秘密。ブラウザやアプリのコードに出さない」とされています（ブラウザでは一時トークンを使います）。',
    remediation: 'ElevenLabs の管理画面（API Keys）で新しいキーを作って差し替え、漏れたキーは削除してください。',
    source: 'ElevenLabs 公式ドキュメント「API Authentication」（"The API key is a secret. Do not ... expose it in any client-side code"）',
  },
  {
    id: 'supabase-secret',
    service: 'Supabase',
    label: 'Supabase の秘密キー（secret / service_role）',
    // SUPABASE_SECRET_KEYS は、複数の secret キーを JSON などでまとめて入れる新方式の変数
    envNames: ['SUPABASE_SECRET_KEY', 'SUPABASE_SECRET_KEYS', 'SUPABASE_SERVICE_ROLE_KEY', 'SUPABASE_SERVICE_KEY'],
    checks: [
      { type: 'token', pattern: /^sb_secret_([A-Za-z0-9_-]+)$/, minRandom: 20 },
      { type: 'jwt-role', secretRoles: ['service_role'], publicRoles: ['anon'] },
    ],
    shapeInText: /sb_secret_[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    // 公式に「公開してよい」とされているキー（RLS のチェックは別に行う）
    publicLookalikes: [{ pattern: /^sb_publishable_/, label: 'publishable キー（公開してよいキー）' }],
    // 新方式の publishable キー（複数をまとめる SUPABASE_PUBLISHABLE_KEYS を含む）と、旧方式の anon キー
    publicEnvNames: ['SUPABASE_PUBLISHABLE_KEY', 'SUPABASE_PUBLISHABLE_KEYS', 'SUPABASE_ANON_KEY'],
    description:
      'Supabase のデータベースのすべてのデータを、アクセス制限（RLS）を無視して読み書きできるキーです。サーバー側だけで使い、ブラウザ・アプリ・ソース管理には絶対に置かないでください。' +
      '（publishable キー・anon キーは公開してよいキーなので、ここでは数えません）',
    remediation:
      'Supabase のダッシュボードの Settings → API Keys で新しい secret キーを作り、すべての場所で差し替えてから、漏れたキーを削除（service_role の場合は無効化）してください。',
    source: 'Supabase 公式ドキュメント「Understanding API keys」（publishable：公開してよい／secret・service_role：バックエンドだけ。RLS を迂回する）',
  },
  {
    id: 'github',
    service: 'GitHub',
    label: 'GitHub のトークン',
    envNames: ['GITHUB_TOKEN', 'GH_TOKEN', 'GITHUB_PAT', 'GITHUB_PERSONAL_ACCESS_TOKEN', 'GITHUB_ACCESS_TOKEN'],
    checks: [
      // 長さは固定しない（GitHub は長さが変わりうるとしており、ghs_ は2026年から長い新形式もある）。短すぎるものだけテスト用とする
      { type: 'token', pattern: /^(?:ghp|gho|ghu|ghs|ghr)_([A-Za-z0-9_.-]+)$/, minRandom: 20 },
      { type: 'token', pattern: /^github_pat_([A-Za-z0-9_]+)$/, minRandom: 20 },
    ],
    shapeInText: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_.-]{20,}|github_pat_[A-Za-z0-9_]{20,}/g,
    publicLookalikes: [],
    description: 'GitHub のリポジトリなどを、あなたの権限で操作できるトークンです。漏れると、コードを読まれたり書き換えられたりするおそれがあります。',
    remediation: 'GitHub の Settings → Developer settings でトークンを削除（無効化）し、必要なら新しく作り直してください。',
    source: 'GitHub Docs「About authentication to GitHub」の token formats（ghp_ / github_pat_ / gho_ / ghu_ / ghs_ / ghr_）',
  },
  {
    id: 'github-app-private-key',
    service: 'GitHub',
    label: 'GitHub App の秘密鍵',
    envNames: ['GITHUB_APP_PRIVATE_KEY', 'GH_APP_PRIVATE_KEY', 'GITHUB_PRIVATE_KEY'],
    checks: [{ type: 'pem-private-key' }],
    publicLookalikes: [],
    description: 'GitHub App として GitHub を操作するための秘密鍵です。漏れると、その App の権限でリポジトリを操作されるおそれがあります。',
    remediation: 'GitHub の App の設定画面で新しい秘密鍵を作って差し替え、漏れた鍵は削除してください。',
    source: 'GitHub Docs（GitHub App の秘密鍵）',
  },
  {
    id: 'stripe',
    service: 'Stripe',
    label: 'Stripe の秘密キー（シークレットキー・制限付きキー）',
    envNames: ['STRIPE_SECRET_KEY', 'STRIPE_API_KEY', 'STRIPE_RESTRICTED_KEY'],
    // sk_test_ / rk_test_（サンドボックス）は実際のお金が動かないため、TEST の語でテスト用に分類される（数えない）
    checks: [{ type: 'token', pattern: /^(?:sk|rk)_(?:live|test)_([A-Za-z0-9]+)$/, minRandom: 20 }],
    shapeInText: /(?:sk|rk)_live_[A-Za-z0-9]{20,}/g,
    publicLookalikes: [{ pattern: /^pk_(?:live|test)_/, label: '公開可能キー（pk_。公開してよいキー）' }],
    publicEnvNames: ['STRIPE_PUBLISHABLE_KEY', 'STRIPE_PUBLIC_KEY'],
    description:
      'Stripe で決済・返金・顧客情報の読み取りなどを、あなたのアカウントの権限で行えるキーです（本番用は sk_live_・rk_live_ で始まります）。サーバー側だけで使い、アプリ・ブラウザ・ソース管理には置かないでください。' +
      '（pk_ で始まる公開可能キーは公開してよいキー、sk_test_・rk_test_ はテスト環境のキーなので、ここでは数えません）',
    remediation: 'Stripe のダッシュボードの API キーのページで、漏れたキーをローテーション（作り直し）するか期限切れにしてください。',
    source:
      'Stripe 公式ドキュメント「API キー」：公開可能キー pk_ は「安全に公開可能」、制限付きキー rk_・シークレットキー sk_ は「いいえ」。本番は _live_、サンドボックスは _test_',
  },
  {
    id: 'aws-secret-access-key',
    service: 'AWS',
    label: 'AWS のシークレットアクセスキー',
    // アクセスキー ID（AKIA…）は、それだけでは秘密としない（ユーザー名のようなもの。シークレットアクセスキーと組で使う）
    envNames: ['AWS_SECRET_ACCESS_KEY'],
    codeNames: ['aws_secret_access_key', 'secretAccessKey'],
    // 接頭辞がないため、名前と組み合わせ、40文字のランダムな値のときだけ本物らしいとする（値の形だけでは探さない）
    checks: [{ type: 'opaque', minLength: 40, maxLength: 40, charset: /^[A-Za-z0-9/+]+$/ }],
    publicLookalikes: [],
    description:
      'AWS をあなたのアカウントの権限で操作できるキー（アクセスキー ID と組で使う秘密の部分）です。漏れると、サーバーを勝手に作られて高額の請求が来たり、データを読まれたりするおそれがあります。',
    remediation: 'AWS のコンソール（IAM）で漏れたアクセスキーを無効化・削除し、必要なら新しいキーを作ってください。できれば、長期のアクセスキーではなく IAM ロールなどの一時的な認証情報に切り替えてください。',
    source:
      'AWS 公式ドキュメント「Manage access keys for IAM users」（アクセスキー ID とシークレットアクセスキーの組。"Do NOT put access keys or credential information in your application files"）',
  },
  {
    id: 'database-url',
    service: 'データベース',
    label: 'データベースの接続情報（パスワード入り）',
    // 名前だけでは秘密としない。URL にユーザー名とパスワードが入っていて、見本・ローカル用でない場合だけ数える
    envNames: ['DATABASE_URL', 'DIRECT_URL'],
    checks: [{ type: 'url-credentials' }],
    publicLookalikes: [],
    description: 'データベースに直接つなぐための接続先です。URL の中にパスワードが入っているため、漏れるとデータベースを直接操作されるおそれがあります。',
    remediation: 'データベースのパスワードを変更し、接続先の URL を新しいものに差し替えてください（Supabase の場合はダッシュボードの Database の設定から）。',
    source: '接続文字列（scheme://ユーザー:パスワード@ホスト）にパスワードが含まれる場合のみ',
  },
];

/** 定義のある環境変数名か（一般的な API キーとしては数えない） */
export function isDefinedSecretName(name: string): boolean {
  return SECRET_DEFINITIONS.some((d) => [...d.envNames, ...(d.codeNames ?? []), ...(d.publicEnvNames ?? [])].some((n) => name === n || name.endsWith(`_${n}`)));
}
