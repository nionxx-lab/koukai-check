// Supabase Management API のレスポンス型。
// 出典: https://github.com/supabase/supabase/blob/master/apps/docs/spec/api_v1_openapi.json
// （GET /v1/projects, GET /v1/projects/{ref}/advisors/security）
//
// Supabase側の仕様変更に備え、この型は supabase/ の外へ直接公開しない。
// 外側のコードは src/types の正規化済み型だけを使う。

export interface ApiProject {
  id: string;
  ref: string;
  organization_id?: string;
  organization_slug?: string;
  name: string;
  region?: string;
  created_at?: string;
  status?: string;
}

/** OpenAPI上は enum だが、splinter 側にある lint（sensitive_columns_exposed 等）が enum に未掲載のため string で受ける。 */
export type ApiLintLevel = 'ERROR' | 'WARN' | 'INFO';

export interface ApiLint {
  name: string;
  title: string;
  level: ApiLintLevel;
  facing: string;
  categories: string[];
  description: string;
  detail: string;
  remediation: string;
  metadata?: {
    schema?: string;
    name?: string;
    entity?: string;
    type?: string;
    [key: string]: unknown;
  };
  cache_key: string;
  observed_at?: string;
}

export interface ApiSecurityAdvisorsResponse {
  lints: ApiLint[];
}
