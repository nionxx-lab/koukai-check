// 日本時間での表示。Node の ICU 構成に依存しないよう、UTC+9 を手計算する（日本に夏時間はない）。

const JST_OFFSET_MS = 9 * 60 * 60 * 1000;

function pad(n: number): string {
  return String(n).padStart(2, '0');
}

/** 例: 2026年10月7日 18:00 */
export function formatJst(iso: string | Date): string | undefined {
  const date = typeof iso === 'string' ? new Date(iso) : iso;
  if (Number.isNaN(date.getTime())) return undefined;
  const d = new Date(date.getTime() + JST_OFFSET_MS);
  return `${d.getUTCFullYear()}年${d.getUTCMonth() + 1}月${d.getUTCDate()}日 ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}

/**
 * 診断結果の取得時刻の説明文。
 * observed_at が複数ある場合は範囲で示し、ない場合はレポート作成時刻を示す。
 */
export function describeObservedAt(observed: { earliest?: string; latest?: string }, fetchedAt: Date): string {
  const earliest = observed.earliest ? formatJst(observed.earliest) : undefined;
  const latest = observed.latest ? formatJst(observed.latest) : undefined;
  if (earliest && latest && earliest !== latest) {
    return `${earliest} 〜 ${latest}（日本時間）のSupabaseの診断結果です。`;
  }
  if (latest) return `${latest}（日本時間）時点のSupabaseの診断結果です。`;
  return `Supabaseから ${formatJst(fetchedAt)}（日本時間）に取得した診断結果です。`;
}
