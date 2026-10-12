// Advisor名 → 初心者向け診断定義 の対応表。
//
// ・Supabase公式の level（ERROR / WARN / INFO）を機械的に変換せず、項目ごとに分類と理由を持つ。
// ・Advisor項目が増減したら、この表に1件追加・修正するだけで済むようにする。
// ・文面の {target} {name} {sensitiveColumns} は template.ts で埋める。
//
// 公式の判定内容は Advisor の診断SQL（supabase/splinter の splinter.sql）と
// Management API の OpenAPI（api_v1_openapi.json）で確認した。

import type { DefinitionStatus, DiagnosticSeverity, ShouldFixBeforeRelease } from '../types/diagnostic.js';

export interface PromptSpec {
  /** AIにお願いする作業の要点 */
  task: string;
  /** 共通の確認項目（Schema・既存Policy・認証方式・アクセス要件）に加えて確認させること */
  extraChecks?: string[];
  /** 共通の注意事項に加えて守らせること */
  extraRules?: string[];
}

export interface DiagnosticDefinition {
  severity: DiagnosticSeverity;
  /** この分類にした理由。公式の level と異なる場合は、その理由を必ず書く */
  severityReason: string;
  /** 省略時は severity から決める（danger→yes / review→review / info→no） */
  shouldFixBeforeRelease?: ShouldFixBeforeRelease;
  /** confirmed: 公式OpenAPIに掲載 / unconfirmed: splinterのみ（APIが返すか未確認） */
  status: Exclude<DefinitionStatus, 'unknown'>;
  /** 対象リソースが特定できないときに {target} {name} に入れる言葉 */
  fallbackTarget: string;
  titleJa: string;
  explanationJa: string;
  remediationJa: string;
  prompt: PromptSpec;
  /** 「診断そのものが一部実行できなかった」ことを表す項目 */
  affectsCompleteness?: boolean;
  /** categories に SECURITY が含まれなくても表示する */
  alwaysInclude?: boolean;
}

const SERVICE_ROLE_CHECK =
  'service_role キー（または secret キー）が、ブラウザやスマホアプリ側のコード、公開される環境変数（NEXT_PUBLIC_ や VITE_ などの接頭辞付き）に含まれていないか';

export const diagnosticDefinitions: Readonly<Record<string, DiagnosticDefinition>> = {
  // ───────────── テーブルのアクセス制限（RLS） ─────────────

  rls_disabled_in_public: {
    severity: 'danger',
    severityReason:
      '公式もERROR。APIから見えるスキーマのテーブルでRLSが無効だと、公開用キー（anonキー）だけで全行を読み書きできる可能性があり、公開時の事故に直結するため「危険」。',
    status: 'confirmed',
    fallbackTarget: '一部のテーブル',
    titleJa: '{target}で、データへのアクセス制限（RLS）が無効です',
    explanationJa:
      'このテーブルでは、誰がどの行を読んだり変更したりできるかを制限する仕組み「RLS（Row Level Security）」が無効になっています。' +
      'Supabaseでは、APIから見えるスキーマ（通常は public）のテーブルに、ブラウザに埋め込まれる公開用のキー（anonキー）を使ってアクセスできます。' +
      'RLSが無効のままだと、アプリの画面を通さずに、このテーブルのデータを読んだり書き換えたりできる可能性があります。',
    remediationJa:
      'テーブルのRLSを有効にし、あわせて「ログインしている本人の行だけ読める」など、アプリに必要な範囲だけを許可するPolicy（アクセスを許可する条件）を作成します。' +
      'RLSを有効にしただけでPolicyがないと、すべてのアクセスが拒否されてアプリが動かなくなることがあるため、Policyとセットで変更してください。' +
      'サーバー側の処理だけで使うテーブルなら、APIから見えないスキーマへ移す方法もあります。',
    prompt: {
      task: '{target}のRLSを有効にし、アプリに必要な範囲だけを許可するPolicyを設計して追加してください。',
      extraChecks: ['{target}を読み書きしているアプリ側のコード（どの画面・処理から、ログイン前とログイン後のどちらで使われているか）'],
      extraRules: ['RLSを有効にするだけでPolicyを作らない変更はしないこと（アプリが動かなくなるため）。'],
    },
  },

  policy_exists_rls_disabled: {
    severity: 'danger',
    severityReason:
      '公式もERROR。Policyを作ってあっても、RLSが無効なので一切適用されていない。「守っているつもりで守れていない」状態のため「危険」。',
    status: 'confirmed',
    fallbackTarget: '一部のテーブル',
    titleJa: '{target}にPolicyはありますが、RLSが無効なので効いていません',
    explanationJa:
      'このテーブルには、アクセスを許可する条件（Policy）が作られていますが、肝心のRLS（行ごとのアクセス制限の仕組み）が無効です。' +
      'この状態ではPolicyは使われず、制限がかかっていないのと同じになります。Policyがあるため「守られている」と誤解しやすい状態です。',
    remediationJa:
      '既存のPolicyがアプリの要件に合っているかを確認してから、テーブルのRLSを有効にします。' +
      '有効にした瞬間からPolicyが適用されるため、Policyが不十分だとアプリの一部が動かなくなる可能性があります。',
    prompt: {
      task: '{target}の既存のPolicyを確認し、要件に合っていればRLSを有効にしてください。不足や誤りがあればPolicyも修正してください。',
      extraChecks: ['{target}に設定されている各Policyが、どの操作（SELECT / INSERT / UPDATE / DELETE）とどのロールを対象にしているか'],
    },
  },

  rls_enabled_no_policy: {
    severity: 'review',
    severityReason:
      '公式はINFO。RLSが有効でPolicyがない状態は、APIからのアクセスがすべて拒否される「安全側」の状態であり、データ漏洩ではないので「危険」にはしない。' +
      'ただし、アプリが動かない原因になりやすく、その回避策として service_role キーをブラウザ側に置く事故につながることがあるため、意図した状態かを確認する「要確認」とする。',
    status: 'confirmed',
    fallbackTarget: '一部のテーブル',
    titleJa: '{target}はRLSが有効ですが、Policyがありません（現在はAPIから誰もアクセスできない状態）',
    explanationJa:
      'このテーブルはRLS（行ごとのアクセス制限）が有効で、アクセスを許可する条件（Policy）が1つもありません。' +
      'この場合、公開用のキーを使ったAPIからのアクセスはすべて拒否されるため、データが外部に漏れる状態ではありません。' +
      'ただし、アプリからこのテーブルを使う予定なら、読み書きできずに動かない原因になります。' +
      'また、動かないのを回避するために強い権限を持つ service_role キーをブラウザ側で使ってしまうと、それ自体が大きな問題になります。',
    remediationJa:
      'このテーブルをブラウザやスマホアプリから使わないのであれば、このままで問題ありません。' +
      '使う場合は、必要な操作（読み取り・追加・更新・削除）ごとに、許可する条件をPolicyとして追加してください。service_role キーで回避しないでください。',
    prompt: {
      task:
        '{target}をアプリ（ブラウザ・スマホアプリ）から使う必要があるかを確認してください。' +
        '必要な場合だけ、必要な操作に限ったPolicyを追加してください。不要な場合は変更せず、その理由を説明してください。',
      extraChecks: [SERVICE_ROLE_CHECK],
    },
  },

  rls_references_user_metadata: {
    severity: 'danger',
    severityReason:
      '公式もERROR。user_metadata はユーザー本人が書き換えられるため、それを使った権限判定は本人の操作で突破できる可能性があり「危険」。',
    status: 'confirmed',
    fallbackTarget: '一部のテーブル',
    titleJa: '{target}のPolicyが、ユーザー自身が書き換えられる情報で権限を判定しています',
    explanationJa:
      'このテーブルのPolicy（アクセスを許可する条件）が、ログインユーザーの「user_metadata」を使って判定しています。' +
      'user_metadata は、ユーザー本人がアプリから書き換えられる情報です。' +
      'たとえば「role が admin なら全件を見られる」という条件だと、ユーザーが自分の user_metadata を書き換えるだけで条件を満たせてしまう可能性があります。',
    remediationJa:
      '権限の判定には、ユーザーが書き換えられない情報（app_metadata や、権限を管理する専用のテーブル）を使うようにPolicyを変更します。',
    prompt: {
      task: '{target}のPolicyで user_metadata を使っている判定を、ユーザーが書き換えられない情報（app_metadata や権限管理用のテーブル）に置き換えてください。',
      extraChecks: ['user_metadata に権限情報を書き込んでいるアプリ側・サーバー側のコード'],
    },
  },

  // ───────────── 権限の境界（ビュー・関数） ─────────────

  security_definer_view: {
    severity: 'danger',
    severityReason:
      '公式もERROR。作成者の権限で動くビューは、元のテーブルのRLSを迂回してデータを読める可能性があるため「危険」。',
    status: 'confirmed',
    fallbackTarget: '一部のビュー',
    titleJa: '{target}が、作成者の権限でデータを読み出す設定（SECURITY DEFINER）になっています',
    explanationJa:
      'このビューは「SECURITY DEFINER」という性質を持っていて、ビューを使った人ではなく、ビューを作った人（多くの場合は管理者権限）の権限でデータを読み出します。' +
      'そのため、元のテーブルにRLS（行ごとのアクセス制限）を設定していても、このビューを経由するとその制限が効かず、本来見られないデータが見えてしまう可能性があります。',
    remediationJa:
      'ビューに security_invoker = on を設定すると、使った人の権限でデータを読むようになり、元のテーブルのRLSが効きます（Postgres 15以上）。' +
      'ビューの利用箇所と元のテーブルのPolicyを確認してから変更してください。APIから使わないビューであれば、APIから見えないスキーマへ移す方法もあります。',
    prompt: {
      task: '{target}を security_invoker で動くようにするなど、元のテーブルのRLSが効く形に修正してください。',
      extraChecks: ['{target}の定義と、参照している元のテーブルのRLS・Policy', 'このビューをアプリのどこで使っているか（ログイン前に使うか）'],
    },
  },

  auth_users_exposed: {
    severity: 'danger',
    severityReason:
      '公式もERROR。メールアドレス等を含む auth.users の情報がAPIから参照できる可能性があり、個人情報の漏洩に直結するため「危険」。',
    status: 'confirmed',
    fallbackTarget: 'ビューなど',
    titleJa: 'ユーザー情報（auth.users）が、{target}を通してAPIから見える可能性があります',
    explanationJa:
      'Supabaseのユーザー情報（メールアドレスなど）が入っている auth.users テーブルが、ビューなどを通じて、公開用のキーで使えるAPIから参照できる状態になっています。' +
      '他のユーザーのメールアドレスなどを取得されるおそれがあります。',
    remediationJa:
      'auth.users を直接参照するビュー等をAPIに公開しないようにします。表示用の情報が必要なら、必要な列だけを持つ profiles のようなテーブルを作り、' +
      'RLSで「本人だけ」「公開してよい列だけ」に制限するのが一般的です。',
    prompt: {
      task: '{target}が auth.users の情報をAPIへ公開しないように修正してください。表示に必要な情報がある場合は、必要な列だけを安全に提供する方法を提案してください。',
      extraChecks: ['{target}の定義と、それを使っている画面・処理'],
    },
  },

  anon_security_definer_function_executable: {
    severity: 'review',
    severityReason:
      '公式はWARN。ログインしていない人が、RLSを迂回できる関数を実行できるため影響は大きくなりうる。一方で、公開機能として意図的に用意したRPCの場合もあるため、断定せず「要確認」。',
    status: 'unconfirmed',
    fallbackTarget: '一部の関数',
    titleJa: 'ログインしていない人が、作成者の権限で動く関数（{target}）を実行できます',
    explanationJa:
      'この関数は「SECURITY DEFINER」で、実行した人ではなく作成者（多くの場合は管理者権限）の権限で動きます。' +
      'さらに、ログインしていない人（anonロール）でもAPI経由（RPC）で実行できます。' +
      '関数の中でRLS（行ごとのアクセス制限）を迂回してデータを読み書きしている場合、誰でもその処理を実行できることになります。' +
      'ログイン前に使う機能として意図的に公開している場合もあります。',
    remediationJa:
      'ログイン前に使う必要がなければ、anon ロールの実行権限（EXECUTE）を外します。必要な場合は、関数の中で入力値や実行者を確認しているか、' +
      '返すデータが公開してよい範囲かを確認してください。SECURITY INVOKER に変更できないかも検討してください。',
    prompt: {
      task: '{target}をログインしていない人が実行できる必要があるかを確認し、不要なら anon の実行権限を外してください。必要な場合は、関数内のチェックと返すデータの範囲を見直してください。',
      extraChecks: ['{target}の定義（中でどのテーブルを読み書きしているか）と、アプリから呼び出している箇所'],
    },
  },

  authenticated_security_definer_function_executable: {
    severity: 'review',
    severityReason:
      '公式はWARN。ログインユーザーなら誰でも実行できるが、多くのアプリは誰でも新規登録できるため、実質的には「誰でも」と同じになることがある。意図した公開かを確認する「要確認」。',
    status: 'unconfirmed',
    fallbackTarget: '一部の関数',
    titleJa: 'ログインしているユーザーなら誰でも、作成者の権限で動く関数（{target}）を実行できます',
    explanationJa:
      'この関数は「SECURITY DEFINER」で、作成者（多くの場合は管理者権限）の権限で動き、ログインしているユーザーなら誰でもAPI経由（RPC）で実行できます。' +
      '誰でも新規登録できるアプリでは、「ログインしている人」は実質的に「誰でも」と同じになることがあります。' +
      '関数の中でRLSを迂回している場合、他のユーザーのデータに触れられる可能性があります。',
    remediationJa:
      '関数の中で「実行した本人のデータだけを扱う」ように auth.uid() 等で確認しているかを見直します。不要な権限であれば実行権限を外すか、SECURITY INVOKER への変更を検討してください。',
    prompt: {
      task: '{target}が、実行した本人に許された範囲のデータだけを扱うようになっているか確認し、必要なら修正してください。',
      extraChecks: ['{target}の定義（中でどのテーブルを読み書きしているか）と、アプリから呼び出している箇所'],
    },
  },

  function_search_path_mutable: {
    severity: 'info',
    severityReason:
      '公式はWARN。悪用には、攻撃者がデータベース内にテーブルや関数を作成できるという前提が必要で、一般的なSupabaseアプリで公開前に必須の修正ではないため「参考」に下げる。修正自体は簡単なので推奨はする。',
    status: 'confirmed',
    fallbackTarget: '一部の関数',
    titleJa: '{target}の search_path（参照先スキーマの順番）が固定されていません',
    explanationJa:
      'この関数は、テーブルや関数を探しにいくスキーマの順番（search_path）が固定されていません。' +
      '条件がそろうと、関数の中で意図しない同じ名前のテーブルや関数が使われる可能性があります。' +
      'ただし、悪用するには攻撃者がデータベース内にオブジェクトを作れる必要があり、一般的なSupabaseアプリですぐに問題になるケースは多くありません。',
    remediationJa:
      '関数の定義に set search_path = \'\' を追加し、関数内では public.テーブル名 のようにスキーマ名付きで参照するようにします。' +
      '修正は比較的簡単なので、時間のあるときに直しておくと安心です。',
    prompt: {
      task: '{target}に search_path を固定する設定を追加し、関数内のテーブルや関数の参照をスキーマ名付きに修正してください。',
      extraChecks: ['{target}の定義と、その中で参照しているテーブル・関数'],
    },
  },

  // ───────────── RLSが効かないオブジェクト ─────────────

  materialized_view_in_api: {
    severity: 'review',
    severityReason:
      '公式はWARN。マテリアライズドビューにはRLSを設定できず、APIから読める可能性がある。ただし、公開してよい集計データを意図的に置くこともあるため「要確認」。',
    status: 'confirmed',
    fallbackTarget: '一部のマテリアライズドビュー',
    titleJa: '{target}がAPIから見える場所にあります（RLSを設定できない種類のビューです）',
    explanationJa:
      'マテリアライズドビュー（集計結果などを保存しておくビュー）には、RLS（行ごとのアクセス制限）を設定できません。' +
      'APIから見えるスキーマに置かれていて読み取り権限があると、中身を誰でも読める可能性があります。公開してよいデータであれば問題ない場合もあります。',
    remediationJa:
      '中身が公開してよいデータかを確認してください。公開すべきでない場合は、anon / authenticated ロールの読み取り権限を外すか、APIから見えないスキーマへ移します。',
    prompt: {
      task: '{target}の中身を公開してよいか確認し、公開すべきでない場合はAPIから読めないように修正してください。',
      extraChecks: ['{target}の定義（元になっているテーブルと列）'],
    },
  },

  foreign_table_in_api: {
    severity: 'review',
    severityReason:
      '公式はWARN。外部テーブルにはRLSが効かず、APIから読める可能性がある。意図した公開の場合もあるため「要確認」。',
    status: 'confirmed',
    fallbackTarget: '一部の外部テーブル',
    titleJa: '{target}がAPIから見える場所にあります（RLSが効かない種類のテーブルです）',
    explanationJa:
      '外部テーブル（別のデータベースやサービスのデータを参照するテーブル）には、RLS（行ごとのアクセス制限）が効きません。' +
      'APIから見えるスキーマにあり読み取り権限があると、参照先のデータを誰でも読める可能性があります。',
    remediationJa:
      '公開してよいデータかを確認し、そうでなければ anon / authenticated ロールの権限を外すか、APIから見えないスキーマへ移します。',
    prompt: {
      task: '{target}をAPIから読める必要があるか確認し、不要ならAPIから読めないように修正してください。',
      extraChecks: ['{target}の参照先と、アプリから使っている箇所'],
    },
  },

  insecure_queue_exposed_in_api: {
    severity: 'danger',
    severityReason:
      '公式もERROR。キューのテーブルがRLSなしでAPIから見えるため、誰でもメッセージを読んだり追加・削除したりできる可能性があり「危険」。',
    status: 'unconfirmed',
    fallbackTarget: '一部のキュー',
    titleJa: 'キュー（{target}）が、アクセス制限なしでAPIから使える状態です',
    explanationJa:
      'キュー（処理待ちのデータを溜めておく仕組み）のテーブルがAPIから見える場所にあり、RLS（行ごとのアクセス制限）が無効です。' +
      '誰でもキューの中身を読んだり、メッセージを追加・削除したりできる可能性があります。',
    remediationJa: 'キューのテーブルのRLSを有効にして適切なPolicyを設定するか、APIからアクセスできないようにします。',
    prompt: {
      task: '{target}をAPIから操作できないようにするか、RLSと必要最小限のPolicyを設定してください。',
      extraChecks: ['{target}にメッセージを送る・受け取る処理がどこにあるか（ブラウザ側かサーバー側か）'],
    },
  },

  pg_graphql_anon_table_exposed: {
    severity: 'review',
    severityReason:
      '公式はWARN。ログイン前の人がテーブル名や列名を見られる状態。実際にどの行を読めるかはRLS次第で、即座に漏洩とは限らないため「要確認」。',
    status: 'unconfirmed',
    fallbackTarget: '一部のテーブル等',
    titleJa: '{target}が、ログインしていない人にもGraphQL経由で見える状態です',
    explanationJa:
      'ログインしていない人（anonロール）が、このテーブル等を読み取る権限を持っています。そのため、GraphQL APIの構造情報から、テーブル名や列名が見える状態です。' +
      '実際にどの行を読めるかはRLS（行ごとのアクセス制限）の設定によりますが、ログイン前の人に読ませる必要がないなら、読み取り権限自体を外す方が安全です。',
    remediationJa:
      'ログイン前に読む必要がなければ、anon ロールの SELECT 権限を外します。GraphQL APIを使っていない場合は、pg_graphql 拡張機能を無効にする方法もあります。',
    prompt: {
      task: '{target}をログインしていない人が読む必要があるか確認し、不要なら anon ロールの読み取り権限を外してください。',
    },
  },

  pg_graphql_authenticated_table_exposed: {
    severity: 'info',
    severityReason:
      '公式はWARN。ログインユーザーにテーブル名や列名が見えるだけで、行へのアクセスはRLSで制御される。ログインユーザーにアプリのテーブルが見えるのは一般的なため「参考」に下げる。',
    status: 'unconfirmed',
    fallbackTarget: '一部のテーブル等',
    titleJa: '{target}が、ログインユーザーにGraphQL経由で見える状態です',
    explanationJa:
      'ログインしているユーザー（authenticatedロール）が、このテーブル等を読み取る権限を持っているため、GraphQL APIの構造情報からテーブル名や列名が見えます。' +
      'アプリで使うテーブルなら通常の状態です。実際にどの行を読めるかはRLSで制御されます。',
    remediationJa:
      'ログインユーザーに見せる必要のないテーブルであれば、authenticated ロールの権限を外します。GraphQL APIを使っていない場合は、pg_graphql 拡張機能の無効化も検討してください。',
    prompt: {
      task: '{target}をログインユーザーが読む必要があるか確認し、不要であれば権限を外してください。',
    },
  },

  // ───────────── 設定・保守 ─────────────

  fkey_to_auth_unique: {
    severity: 'review',
    severityReason:
      '公式はERROR。ただしデータ漏洩ではなく、Supabaseが auth スキーマを更新したときにエラーや障害の原因になるという保守性の問題のため、「要確認」に下げる。',
    status: 'unconfirmed',
    fallbackTarget: '一部のテーブル',
    titleJa: '{target}が、Supabase管理の auth スキーマの制約に依存しています',
    explanationJa:
      'このテーブルの外部キーが、Supabaseが管理する auth スキーマの一意制約（重複しない値を保証する制約）を参照しています。' +
      'Supabase側が auth スキーマを更新したときに、エラーになったり更新できなくなったりする原因になります。データ漏洩に直結するものではありません。',
    remediationJa: 'auth.users の主キー（id）を参照する形にするか、自分で管理する profiles のようなテーブルを経由する形に変更します。',
    prompt: {
      task: '{target}の外部キーを、auth.users の主キー（id）を参照する形などに変更してください。',
      extraChecks: ['{target}の外部キー定義と、その列を使っているアプリ側のコード'],
    },
  },

  extension_in_public: {
    severity: 'info',
    severityReason:
      '公式はWARN。拡張機能の関数等がAPIから見える場所に置かれる構成上の問題で、すぐにデータ漏洩につながるものではないため「参考」。',
    status: 'confirmed',
    fallbackTarget: '一部の拡張機能',
    titleJa: '拡張機能（{name}）が public スキーマに入っています',
    explanationJa:
      'Postgresの拡張機能が、アプリのテーブルと同じ public スキーマにインストールされています。拡張機能が作る関数などがAPIから見える場所に置かれるため、望ましくない構成とされています。' +
      'すぐにデータが漏れる状態ではありません。',
    remediationJa:
      '可能であれば extensions スキーマへ移します。拡張機能によっては移動できないものや、移動するとアプリが動かなくなるものもあるため、利用箇所を確認してから行ってください。',
    prompt: {
      task: '拡張機能 {name} を extensions スキーマへ移せるか確認し、安全に移せる場合は移動してください。',
      extraChecks: ['拡張機能 {name} の関数や型を使っている箇所'],
    },
  },

  extension_versions_outdated: {
    severity: 'info',
    severityReason: '公式はWARN。古いバージョンには修正済みの不具合が残っている可能性があるが、直ちに公開を止める理由ではないため「参考」。',
    status: 'unconfirmed',
    fallbackTarget: '一部の拡張機能',
    titleJa: '拡張機能（{name}）のバージョンが古くなっています',
    explanationJa: 'インストールされている拡張機能のバージョンが、利用可能な最新版より古くなっています。古いバージョンには、修正済みの不具合や脆弱性が残っている可能性があります。',
    remediationJa: '更新内容を確認したうえで、拡張機能をアップデートします。アップデートで動作が変わることがあるため、テスト環境で確認してから行うと安全です。',
    prompt: {
      task: '拡張機能 {name} を更新した場合の影響を調べ、安全に更新する手順を提案してください。',
    },
  },

  unsupported_reg_types: {
    severity: 'info',
    severityReason:
      '公式はSECURITYカテゴリのWARNだが、データ漏洩には直結せず、Postgresのアップグレードを妨げる要因であるため「参考」。',
    status: 'confirmed',
    fallbackTarget: '一部のテーブル',
    titleJa: '{target}で、データベースのアップグレード時に問題になる型が使われています',
    explanationJa:
      'このテーブルの列で、Postgresのアップグレードに対応していない reg 系の型が使われています。' +
      'セキュリティ上の直接の問題ではありませんが、将来Supabaseのデータベースをアップグレードできない原因になります。',
    remediationJa: 'text 型など、アップグレードに対応した型への置き換えを検討してください。',
    prompt: {
      task: '{target}で reg 系の型を使っている列を、アップグレードに対応した型へ置き換える方法を提案してください。',
    },
  },

  // ───────────── プロジェクト設定（SQL以外の診断） ─────────────

  leaked_service_key: {
    severity: 'danger',
    severityReason:
      'service_role キーはRLSをすべて無視できる管理者用のキーで、漏洩していれば全データを読み書きされる可能性があるため「危険」。（公式 level はAPI応答に従う）',
    status: 'confirmed',
    fallbackTarget: 'このプロジェクト',
    alwaysInclude: true,
    titleJa: 'service_role キーが漏洩している可能性があります',
    explanationJa:
      'Supabaseが、このプロジェクトの service_role キー（RLSをすべて無視できる、管理者用の強力なキー）が外部に漏れている可能性を検出しました。' +
      'このキーを持っている人は、すべてのデータを読み書きできます。',
    remediationJa:
      'Supabaseのダッシュボードでキーを再発行（ローテーション）し、古いキーを使えないようにします。' +
      'そのうえで、キーがブラウザ側のコード、公開リポジトリ、ログなどに含まれていないかを確認し、サーバー側だけで使う構成にします。',
    prompt: {
      task:
        'service_role キー（secret キー）がコードや公開されるファイルに含まれていないか調査し、含まれている箇所を取り除いて、サーバー側だけで使う構成に修正してください。' +
        'キーの再発行は Supabase ダッシュボードで私が行うので、その手順と、再発行後に更新が必要な場所を説明してください。',
      extraChecks: [SERVICE_ROLE_CHECK, 'Gitの履歴や公開リポジトリに、キーがコミットされたことがないか'],
      extraRules: ['キーの値そのものを、出力・ログ・コミットに含めないこと。'],
    },
  },

  ssl_not_enforced: {
    severity: 'review',
    severityReason:
      'データベースへの直接接続が暗号化されない可能性がある。APIを通したアクセス（supabase-js 等）には影響せず、意図的に無効にしている場合もあるため「要確認」。',
    status: 'confirmed',
    fallbackTarget: 'このプロジェクト',
    alwaysInclude: true,
    titleJa: 'データベースへの直接接続で、通信の暗号化（SSL）が必須になっていません',
    explanationJa:
      'アプリやツールがデータベースに直接接続するときに、通信の暗号化（SSL）が必須になっていません。' +
      '暗号化されていない接続を使うと、通信経路で接続情報やデータを盗み見られるおそれがあります。APIを通したアクセス（supabase-js など）には影響しません。',
    remediationJa:
      'ダッシュボードのデータベース設定で SSL の強制（SSL Enforcement）を有効にします。有効にすると、SSLに対応していない古いツールからは接続できなくなる場合があります。',
    prompt: {
      task: 'このプロジェクトのデータベースに直接接続している箇所（サーバー、バッチ、ツール等）がSSLに対応しているか確認し、SSLを強制しても問題ないか判断してください。',
      extraChecks: ['DATABASE_URL などの接続文字列を使っている箇所と、その接続設定（sslmode など）'],
    },
  },

  vulnerable_postgres_version: {
    severity: 'review',
    severityReason:
      '既知の脆弱性を含むバージョンの可能性があり、アップグレードが推奨される。影響は脆弱性の内容によるため「要確認」。',
    status: 'confirmed',
    fallbackTarget: 'このプロジェクト',
    alwaysInclude: true,
    titleJa: 'データベース（Postgres）のバージョンに、既知の脆弱性がある可能性があります',
    explanationJa:
      '使っているPostgresのバージョンに、修正版が提供されている脆弱性がある可能性があります。Supabaseのダッシュボードからアップグレードできます。',
    remediationJa:
      'ダッシュボードのインフラ設定からPostgresをアップグレードします。アップグレード中は一時的にデータベースが使えなくなることがあるため、利用者の少ない時間帯に行ってください。',
    prompt: {
      task: 'Postgresのアップグレードで影響を受けそうな箇所（拡張機能、型、関数）を洗い出し、安全にアップグレードする手順を提案してください。',
    },
  },

  auth_leaked_password_protection: {
    severity: 'info',
    severityReason: '設定改善の提案であり、プランによっては利用できない機能のため「参考」。',
    status: 'confirmed',
    fallbackTarget: 'このプロジェクト',
    alwaysInclude: true,
    titleJa: '流出したパスワードのチェック機能が無効です',
    explanationJa:
      '過去に流出したことがあるパスワード（HaveIBeenPwned のデータ）で新規登録・変更するのを防ぐ機能が無効です。' +
      '有効にすると、使い回された弱いパスワードによる乗っ取りを減らせます。この機能は有料プランでのみ使える場合があります。',
    remediationJa: 'ダッシュボードの Authentication 設定で、漏洩パスワードの保護（Leaked password protection）を有効にします。',
    prompt: {
      task: '流出パスワードのチェックを有効にした場合に、アプリの新規登録・パスワード変更画面で必要になるエラー表示の対応を確認してください。',
    },
  },

  auth_otp_long_expiry: {
    severity: 'info',
    severityReason: '認証設定の改善提案で、直ちに公開を止める理由ではないため「参考」。',
    status: 'confirmed',
    fallbackTarget: 'このプロジェクト',
    alwaysInclude: true,
    titleJa: 'メールで送るワンタイムコード（OTP）の有効期限が長めです',
    explanationJa: 'メール認証などで使うワンタイムコードやリンクの有効期限が長く設定されています。有効期限が長いほど、第三者に使われる機会が増えます。',
    remediationJa: 'ダッシュボードの Authentication 設定で、OTP の有効期限を短く（1時間以内など）します。',
    prompt: { task: 'OTPの有効期限を短くした場合に、アプリの登録・ログインの流れで困る点がないか確認してください。' },
  },

  auth_otp_short_length: {
    severity: 'info',
    severityReason: '認証設定の改善提案で、直ちに公開を止める理由ではないため「参考」。',
    status: 'confirmed',
    fallbackTarget: 'このプロジェクト',
    alwaysInclude: true,
    titleJa: 'ワンタイムコード（OTP）の桁数が短めです',
    explanationJa: 'ワンタイムコードの桁数が短いと、総当たりで当てられる可能性が高くなります。',
    remediationJa: 'ダッシュボードの Authentication 設定で、OTP の桁数を増やします。',
    prompt: { task: 'OTPの桁数を増やした場合に、アプリの入力画面で対応が必要な箇所がないか確認してください。' },
  },

  auth_insufficient_mfa_options: {
    severity: 'info',
    severityReason: '二要素認証の選択肢に関する改善提案で、多くの個人開発アプリでは必須ではないため「参考」。',
    status: 'confirmed',
    fallbackTarget: 'このプロジェクト',
    alwaysInclude: true,
    titleJa: '二要素認証（MFA）の選択肢が少ない設定です',
    explanationJa: 'パスワードに加えて別の方法で本人確認する「二要素認証」の選択肢が少ない設定になっています。重要なデータを扱うアプリでは、有効にすると乗っ取りの被害を減らせます。',
    remediationJa: '必要に応じて、ダッシュボードの Authentication 設定で MFA の方式を追加します。',
    prompt: { task: 'このアプリに二要素認証が必要か判断する材料を整理し、導入する場合の実装方針を提案してください。' },
  },

  auth_password_policy_missing: {
    severity: 'info',
    severityReason: '認証設定の改善提案で、直ちに公開を止める理由ではないため「参考」。',
    status: 'confirmed',
    fallbackTarget: 'このプロジェクト',
    alwaysInclude: true,
    titleJa: 'パスワードの強さのルールが設定されていません',
    explanationJa: '使える文字の種類などのパスワードのルールが設定されていないため、推測されやすい弱いパスワードでも登録できます。',
    remediationJa: 'ダッシュボードの Authentication 設定で、パスワードの要件を設定します。',
    prompt: { task: 'パスワードの要件を設定した場合に、アプリの登録画面で必要になる案内やエラー表示を確認してください。' },
  },

  password_requirements_min_length: {
    severity: 'info',
    severityReason: '認証設定の改善提案で、直ちに公開を止める理由ではないため「参考」。',
    status: 'confirmed',
    fallbackTarget: 'このプロジェクト',
    alwaysInclude: true,
    titleJa: 'パスワードの最小文字数が短めです',
    explanationJa: 'パスワードの最小文字数が短いと、推測や総当たりで破られやすくなります。',
    remediationJa: 'ダッシュボードの Authentication 設定で、最小文字数を増やします（8文字以上が目安）。',
    prompt: { task: 'パスワードの最小文字数を増やした場合に、アプリの登録画面で必要になる案内やエラー表示を確認してください。' },
  },

  network_restrictions_not_set: {
    severity: 'info',
    severityReason: 'データベースの直接接続元を絞る追加の防御策で、未設定でも直ちに問題とは限らないため「参考」。',
    status: 'confirmed',
    fallbackTarget: 'このプロジェクト',
    alwaysInclude: true,
    titleJa: 'データベースへ直接接続できる場所（IPアドレス）が制限されていません',
    explanationJa:
      'データベースへの直接接続を、特定のIPアドレスからだけに制限する設定がされていません。パスワードが漏れた場合の被害を減らすための追加の防御策です。APIを通したアクセスには影響しません。',
    remediationJa: '直接接続する場所が決まっている場合は、ダッシュボードのネットワーク制限（Network Restrictions）で接続元を限定します。',
    prompt: { task: 'このプロジェクトのデータベースに直接接続している場所を洗い出し、接続元を制限できるか判断してください。' },
  },

  pitr_not_enabled: {
    severity: 'info',
    severityReason: 'セキュリティ設定ではなくバックアップ機能の有無で、有料の追加機能でもあるため「参考」。',
    status: 'confirmed',
    fallbackTarget: 'このプロジェクト',
    alwaysInclude: true,
    titleJa: '任意の時点に戻せるバックアップ（PITR）が無効です',
    explanationJa: '任意の時点のデータに戻せるバックアップ機能（ポイントインタイムリカバリ）が無効です。誤ってデータを消したときに、細かい時点まで戻せない可能性があります。',
    remediationJa: '必要に応じて、ダッシュボードで PITR を有効にします（有料の追加機能です）。少なくとも、日次バックアップから戻す手順は確認しておきましょう。',
    prompt: { task: 'このアプリのデータが消えた場合の復旧手順を整理し、PITRが必要かを判断する材料を提示してください。' },
  },

  log_connections_not_enabled: {
    severity: 'info',
    severityReason: '監査用のログ設定で、直ちに公開を止める理由ではないため「参考」。',
    status: 'confirmed',
    fallbackTarget: 'このプロジェクト',
    alwaysInclude: true,
    titleJa: 'データベースへの接続の記録（ログ）が無効です',
    explanationJa: 'データベースに誰がいつ接続したかの記録が残らない設定です。問題が起きたときの原因調査がしにくくなります。',
    remediationJa: '必要に応じて、データベースの設定で接続ログを有効にします。',
    prompt: { task: 'データベースの接続ログを有効にする方法と、その影響（ログ量など）を説明してください。' },
  },

  // ───────────── 診断自体が実行できなかったことを表す項目 ─────────────

  advisor_check_unavailable: {
    severity: 'info',
    severityReason: 'セキュリティ上の指摘ではなく、Supabase側で一部の診断を実行できなかったことを表す。安全と誤解させないよう、診断が不完全であることを示す。',
    shouldFixBeforeRelease: 'review',
    status: 'confirmed',
    fallbackTarget: 'このプロジェクト',
    alwaysInclude: true,
    affectsCompleteness: true,
    titleJa: 'Supabaseの診断の一部を実行できませんでした',
    explanationJa:
      'Supabaseが一部の診断項目を実行できなかったと報告しています。そのため、問題があっても今回の結果に表示されていない可能性があります。',
    remediationJa: '時間をおいて再度チェックしてください。続く場合は、Supabaseダッシュボードの Advisors 画面で状態を確認してください。',
    prompt: { task: 'Supabase の Security Advisor が一部実行できなかった原因として考えられることと、確認方法を説明してください。' },
  },

  project_not_active: {
    severity: 'info',
    severityReason: 'セキュリティ上の指摘ではなく、プロジェクトが停止中のため診断できないことを表す。',
    shouldFixBeforeRelease: 'review',
    status: 'confirmed',
    fallbackTarget: 'このプロジェクト',
    alwaysInclude: true,
    affectsCompleteness: true,
    titleJa: 'プロジェクトが停止中のため、診断できない項目があります',
    explanationJa: 'このプロジェクトは一時停止中などで動いていないため、データベースの設定を診断できません。今回の結果は不完全です。',
    remediationJa: 'Supabaseダッシュボードでプロジェクトを再開してから、もう一度チェックしてください。',
    prompt: { task: '停止中のSupabaseプロジェクトを再開する手順と、再開時の注意点を説明してください。' },
  },

  db_not_reachable: {
    severity: 'info',
    severityReason: 'セキュリティ上の指摘ではなく、データベースに接続できず診断できないことを表す。',
    shouldFixBeforeRelease: 'review',
    status: 'confirmed',
    fallbackTarget: 'このプロジェクト',
    alwaysInclude: true,
    affectsCompleteness: true,
    titleJa: 'データベースに接続できないため、診断できない項目があります',
    explanationJa: 'Supabaseがデータベースに接続できなかったため、テーブルやPolicyの診断を実行できていない可能性があります。今回の結果は不完全です。',
    remediationJa: '時間をおいて再度チェックしてください。続く場合は、Supabaseダッシュボードでデータベースの状態を確認してください。',
    prompt: { task: 'Supabaseのデータベースに接続できない場合に考えられる原因と、確認方法を説明してください。' },
  },

  db_connection_failing: {
    severity: 'info',
    severityReason: 'セキュリティ上の指摘ではなく、データベース接続の失敗により診断が不完全な可能性を表す。',
    shouldFixBeforeRelease: 'review',
    status: 'confirmed',
    fallbackTarget: 'このプロジェクト',
    alwaysInclude: true,
    affectsCompleteness: true,
    titleJa: 'データベースへの接続が失敗しているため、診断が不完全な可能性があります',
    explanationJa: 'データベースへの接続が失敗している状態のため、一部の診断を実行できていない可能性があります。',
    remediationJa: 'Supabaseダッシュボードでデータベースの状態を確認し、回復してからもう一度チェックしてください。',
    prompt: { task: 'Supabaseのデータベース接続が失敗する場合に考えられる原因と、確認方法を説明してください。' },
  },

  instance_db_down: {
    severity: 'info',
    severityReason: 'セキュリティ上の指摘ではなく、データベースが停止しているため診断できないことを表す。',
    shouldFixBeforeRelease: 'review',
    status: 'confirmed',
    fallbackTarget: 'このプロジェクト',
    alwaysInclude: true,
    affectsCompleteness: true,
    titleJa: 'データベースが停止しているため、診断できない項目があります',
    explanationJa: 'データベースが停止しているため、テーブルやPolicyの診断を実行できていません。今回の結果は不完全です。',
    remediationJa: 'Supabaseダッシュボードでデータベースの状態を確認し、回復してからもう一度チェックしてください。',
    prompt: { task: 'Supabaseのデータベースが停止している場合に考えられる原因と、確認方法を説明してください。' },
  },

  // ───────────── 公式OpenAPIに未掲載（Phase 1 で「実APIで要確認」とした項目） ─────────────
  // API が実際にこの name を返した場合に備えて定義だけ用意している。MVP の必須項目ではない。

  sensitive_columns_exposed: {
    severity: 'danger',
    severityReason:
      '公式もERROR（splinter）。個人情報や認証情報らしき列を持つテーブルがRLSなしでAPIから見える状態で、漏洩時の影響が大きいため「危険」。',
    status: 'unconfirmed',
    fallbackTarget: '一部のテーブル',
    titleJa: '{target}に個人情報らしき列があり、アクセス制限（RLS）なしでAPIから見える状態です',
    explanationJa:
      'このテーブルには、メールアドレスや電話番号、パスワードなど、個人情報や認証情報の可能性がある列が含まれています{sensitiveColumns}。' +
      'さらに、RLS（行ごとのアクセス制限）が無効のままAPIから見える場所にあるため、これらの情報を読まれる可能性があります。' +
      '列名から自動で判定しているため、実際には機密情報でない場合もあります。',
    remediationJa:
      'テーブルのRLSを有効にして、本人など必要な人だけが読めるPolicyを設定します。公開する必要のない列は、別のテーブルへ分けることも検討してください。',
    prompt: {
      task: '{target}のRLSを有効にし、機密性の高い列を必要な人だけが読めるようにPolicyを設計してください。',
      extraChecks: ['該当する列{sensitiveColumns}を、アプリのどの画面・処理で使っているか'],
      extraRules: ['RLSを有効にするだけでPolicyを作らない変更はしないこと（アプリが動かなくなるため）。'],
    },
  },

  rls_policy_always_true: {
    severity: 'danger',
    severityReason:
      '公式はWARN。追加・更新・削除の操作を無条件で許可するPolicyで、RLSが実質的に無効になっているため、独自に「危険」へ引き上げる。' +
      '（公開読み取りのために意図的に使われる SELECT の USING (true) は、公式の診断側で対象外になっている）',
    status: 'unconfirmed',
    fallbackTarget: '一部のテーブル',
    titleJa: '{target}に、誰に対しても常に許可するPolicyがあります',
    explanationJa:
      'このテーブルには「USING (true)」のように、条件が常に成立するPolicy（アクセスを許可する条件）が、追加・更新・削除のいずれかの操作に設定されています。' +
      'RLS（行ごとのアクセス制限）は有効でも、実質的には誰でもデータを書き換えたり消したりできる可能性があります。',
    remediationJa:
      'Policyの条件を「本人の行だけ（auth.uid() = user_id など）」のように、必要な人だけに絞ります。',
    prompt: {
      task: '{target}の、条件が常に成立するPolicyを、必要な人だけに許可する条件へ修正してください。',
      extraChecks: ['該当するPolicyが対象にしている操作とロール'],
    },
  },

  public_bucket_allows_listing: {
    severity: 'review',
    severityReason:
      '公式はWARN。ファイルの一覧を取得できるため、他人がアップロードしたファイルの存在や名前が分かる。ファイルの公開自体は意図的な場合が多いため「要確認」。',
    status: 'unconfirmed',
    fallbackTarget: '一部の公開バケット',
    titleJa: '公開Storageバケット（{name}）のファイル一覧を、誰でも取得できます',
    explanationJa:
      'このStorageバケットは公開設定（URLを知っていれば誰でもファイルを見られる）になっていて、さらにファイルの一覧を取得できるPolicyがあります。' +
      '公開バケットのファイルを表示するだけなら一覧の権限は不要で、この状態だと、他の人がアップロードしたファイルの存在や名前まで知られてしまう可能性があります。',
    remediationJa: 'ファイルのURLを表示するだけが目的なら、storage.objects に対する広い SELECT のPolicyを削除するか、条件を絞ります。',
    prompt: {
      task: 'バケット {name} について、ファイル一覧の取得が本当に必要か確認し、不要なら storage.objects の広い SELECT Policy を削除または制限してください。',
      extraChecks: ['アプリがこのバケットのファイル一覧（list）を使っている箇所があるか'],
    },
  },
};

export function getDefinition(advisorName: string): DiagnosticDefinition | undefined {
  return Object.prototype.hasOwnProperty.call(diagnosticDefinitions, advisorName)
    ? diagnosticDefinitions[advisorName]
    : undefined;
}
