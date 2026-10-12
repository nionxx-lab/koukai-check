export type SupabaseErrorKind =
  | 'invalid_token' // 401
  | 'forbidden' // 403: トークンの権限不足、または対象外プロジェクト
  | 'not_found' // 404: プロジェクトが存在しない / ref の入力ミス
  | 'rate_limited' // 429
  | 'server_error' // 5xx
  | 'network' // 接続できない・タイムアウト
  | 'unexpected_response'; // JSONとして読めない、または想定外の形（API仕様変更の可能性）

export class SupabaseApiError extends Error {
  readonly kind: SupabaseErrorKind;
  readonly status?: number;
  readonly endpoint: string;

  constructor(kind: SupabaseErrorKind, endpoint: string, message: string, status?: number) {
    super(message);
    this.name = 'SupabaseApiError';
    this.kind = kind;
    this.endpoint = endpoint;
    this.status = status;
  }
}

export function kindFromStatus(status: number): SupabaseErrorKind {
  if (status === 401) return 'invalid_token';
  if (status === 403) return 'forbidden';
  if (status === 404) return 'not_found';
  if (status === 429) return 'rate_limited';
  if (status >= 500) return 'server_error';
  return 'unexpected_response';
}
