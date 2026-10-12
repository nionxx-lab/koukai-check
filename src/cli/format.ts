// Phase 2 の確認用テキスト出力。Phase 3 で HTML レポートに置き換える。

import type { Diagnostic, DiagnosticReport, DiagnosticSeverity, ShouldFixBeforeRelease } from '../types/diagnostic.js';

const SEVERITY_LABEL: Record<DiagnosticSeverity, string> = {
  danger: '🔴 危険',
  review: '🟠 要確認',
  info: '🔵 参考',
};

const SHOULD_FIX_LABEL: Record<ShouldFixBeforeRelease, string> = {
  yes: '公開前に修正することをおすすめします。',
  review: '公開前に、意図した設定かどうか確認することをおすすめします。',
  no: 'すぐに公開を止める必要はありませんが、知っておくと安心です。',
};

function formatDiagnostic(d: Diagnostic, index: number, showPrompt: boolean): string {
  const lines = [
    `── ${index + 1}. ${SEVERITY_LABEL[d.severity]}  ${d.titleJa}`,
    '',
    `【なぜ問題か】\n${d.explanationJa}`,
    '',
    `【公開前に直すべきか】\n${SHOULD_FIX_LABEL[d.shouldFixBeforeRelease]}`,
    '',
    `【修正方針】\n${d.remediationJa}`,
  ];
  if (showPrompt) {
    lines.push('', '【AIに直してもらう指示】', d.aiFixPrompt);
  }
  lines.push(
    '',
    `（Supabase: ${d.advisorName} / 公式の重要度 ${d.officialSeverity ?? '不明'}` +
      `${d.definitionStatus === 'unconfirmed' ? ' / 定義は未検証の項目' : ''}${d.observedAt ? ` / ${d.observedAt} 時点` : ''}）`,
  );
  return lines.join('\n');
}

export function formatReport(report: DiagnosticReport, options: { showPrompt?: boolean } = {}): string {
  const showPrompt = options.showPrompt ?? true;
  const out: string[] = [];
  out.push('公開前チェック', '', report.headlineJa, '');
  out.push(`危険    ${report.counts.danger}件`, `要確認  ${report.counts.review}件`, `参考    ${report.counts.info}件`, '');

  if (report.observedAt.latest) out.push(`この診断結果は ${report.observedAt.latest} 時点のSupabaseの診断結果です。`);
  if (report.token?.noticeJa) out.push(`注意: ${report.token.noticeJa}`);
  if (report.incomplete) out.push('注意: 診断結果の一部を読み取れなかったか、Supabase側で実行できなかった診断があります。結果が不完全な可能性があります。');
  if (report.unknownAdvisorNames.length > 0) {
    out.push(`このツールが未対応の診断項目が含まれています: ${report.unknownAdvisorNames.join(', ')}`);
  }
  out.push(report.disclaimerJa, '');

  report.diagnostics.forEach((d, i) => out.push(formatDiagnostic(d, i, showPrompt), ''));
  return out.join('\n');
}
