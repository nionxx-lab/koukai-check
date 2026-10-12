// モックの応答。形は公式OpenAPI（api_v1_openapi.json）と splinter.sql の出力に合わせている。
// 実APIで確認した値ではない点に注意。

export const PROJECT_A = {
  id: 'abcdefghijklmnopqrst',
  ref: 'abcdefghijklmnopqrst',
  organization_id: 'org1',
  organization_slug: 'org1',
  name: 'my-ai-app',
  region: 'ap-northeast-1',
  created_at: '2026-09-01T00:00:00Z',
  status: 'ACTIVE_HEALTHY',
};

export const PROJECT_B = {
  ...PROJECT_A,
  id: 'zyxwvutsrqponmlkjihg',
  ref: 'zyxwvutsrqponmlkjihg',
  name: 'side-project',
};

export const LINTS_WITH_ISSUES = {
  lints: [
    {
      name: 'rls_disabled_in_public',
      title: 'Sample: RLS is off for a public table',
      level: 'ERROR',
      facing: 'EXTERNAL',
      categories: ['SECURITY'],
      description: 'Sample description: a table in a schema served by the API has row level security turned off.',
      detail: 'Sample detail: `public.profiles` is reachable from the API and RLS is off.',
      remediation: 'https://supabase.com/docs/guides/database/database-linter?lint=0013_rls_disabled_in_public',
      metadata: { schema: 'public', name: 'profiles', type: 'table' },
      cache_key: 'rls_disabled_in_public_public_profiles',
    },
    {
      name: 'sensitive_columns_exposed',
      title: 'Sample: sensitive columns reachable via the API',
      level: 'ERROR',
      facing: 'EXTERNAL',
      categories: ['SECURITY'],
      description: 'Sample description: an API-reachable table without RLS has columns that may hold personal or secret data.',
      detail: 'Sample detail: `public.profiles` is reachable from the API without RLS and has columns such as email, phone.',
      remediation: 'https://supabase.com/docs/guides/database/database-linter?lint=0023_sensitive_columns_exposed',
      metadata: { schema: 'public', name: 'profiles', type: 'table', sensitive_columns: ['email', 'phone'] },
      cache_key: 'sensitive_columns_exposed_public_profiles',
    },
    {
      name: 'public_bucket_allows_listing',
      title: 'Sample: public bucket file list is readable',
      level: 'WARN',
      facing: 'EXTERNAL',
      categories: ['SECURITY'],
      description: 'Sample description: a public bucket has a wide SELECT policy on `storage.objects`, so anyone can read its file list.',
      detail: 'Sample detail: public bucket `avatars` has 1 wide SELECT policy on `storage.objects`.',
      remediation: 'https://supabase.com/docs/guides/database/database-linter?lint=0025_public_bucket_allows_listing',
      metadata: { schema: 'storage', name: 'avatars', type: 'bucket', bucket_id: 'avatars', policy_count: 1 },
      cache_key: 'public_bucket_allows_listing_avatars',
    },
    {
      name: 'rls_enabled_no_policy',
      title: 'Sample: RLS is on but there are no policies',
      level: 'INFO',
      facing: 'EXTERNAL',
      categories: ['SECURITY'],
      description: 'Sample description: row level security is on for a table, but it has no policies yet.',
      detail: 'Sample detail: `public.notes` has RLS on and no policies.',
      remediation: 'https://supabase.com/docs/guides/database/database-linter?lint=0008_rls_enabled_no_policy',
      metadata: { schema: 'public', name: 'notes', type: 'table' },
      cache_key: 'rls_enabled_no_policy_public_notes',
    },
    {
      name: 'auth_leaked_password_protection',
      title: 'Sample: leaked password check is off',
      level: 'WARN',
      facing: 'EXTERNAL',
      categories: ['SECURITY'],
      description: 'Sample description: the leaked password check in Auth is turned off.',
      detail: 'Sample detail: the leaked password check in the Auth settings is off.',
      remediation: 'https://supabase.com/docs/guides/auth/password-security',
      metadata: { type: 'auth', entity: 'Auth' },
      cache_key: 'auth_leaked_password_protection',
    },
  ],
};
