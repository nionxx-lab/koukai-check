// Claude Code / Codex に貼り付ける修正依頼文を、固定テンプレートから組み立てる。
// 外部のAI APIは使わない。
//
// 方針:
// ・いきなりSQLを書かせない。まず Schema・既存Policy・認証方式・アクセス要件を確認させる。
// ・要件が分からなければ、変更前にユーザーへ説明・確認させる。
// ・既存機能を壊さないこと、本番DBへ直接SQLを実行しないことを明記する。

import type { PromptSpec } from './definitions.js';
import { fillTemplate, sanitizeForPrompt, type TemplateContext } from './template.js';

export interface PromptInput {
  advisorName: string;
  spec: PromptSpec;
  ctx: TemplateContext;
  /** 公式の英語の指摘文（対象名入り） */
  officialDetail: string;
  helpUrl?: string;
}

const COMMON_CHECKS = [
  '現在のSchema（{target}の定義と、関連するテーブル・ビュー・関数）',
  '既存のRLS Policyや権限設定（supabase/migrations 内のSQL、またはSupabaseダッシュボード上の定義）',
  'アプリの認証方式（Supabase Authを使っているか、ログインせずに使える画面があるか、service_role キーをどこで使っているか）',
  'アプリ側のアクセス要件（誰が、どのデータを、読む・追加する・更新する・削除する必要があるか）',
];

const COMMON_RULES = [
  '既存機能を壊さないこと。',
  '推測だけで変更しないこと。アクセス要件が判断できない場合は、変更する前に、分かったことと不明な点を私に説明して確認を取ること。',
  '変更はマイグレーションファイルなど、レビューできる形で残すこと。本番のデータベースへ直接SQLを実行しないこと。',
  'service_role キーをブラウザやスマホアプリ側のコードで使って回避しないこと。',
];

const FINAL_REPORT = [
  '何を変更したか',
  'なぜその変更が必要だったか',
  '確認すべきテスト（ログインしていない状態・別のユーザーでログインした状態で、見えてはいけないデータが見えないこと、アプリの既存機能が動くことの確認方法を含む）',
];

function numbered(items: string[]): string {
  return items.map((item, i) => `${i + 1}. ${item}`).join('\n');
}

function bullets(items: string[]): string {
  return items.map((item) => `- ${item}`).join('\n');
}

/** 修正依頼文の組み立て（Supabase の診断・フォルダのチェックで共通の形） */
export interface FixPromptParts {
  /** 冒頭の状況説明（1行ずつ） */
  intro: string[];
  task: string;
  checks: string[];
  rules: string[];
  /** 利用者（開発者）自身が行う操作。AIには行わせない（キーの無効化・再発行など） */
  ownerActions?: string[];
  finalReport: string[];
}

export function composeFixPrompt(parts: FixPromptParts): string {
  const lines: string[] = [...parts.intro];
  lines.push('');
  lines.push('## お願いしたいこと');
  lines.push(parts.task);
  lines.push('');
  lines.push('## 変更する前に、まず確認してほしいこと');
  lines.push(numbered(parts.checks));
  lines.push('');
  lines.push('## 守ってほしいこと');
  lines.push(bullets(parts.rules));
  if (parts.ownerActions && parts.ownerActions.length > 0) {
    lines.push('');
    lines.push('## 私（開発者）が自分で行うこと（あなたは行わないでください）');
    lines.push(bullets(parts.ownerActions));
  }
  lines.push('');
  lines.push('## 最後に説明してほしいこと');
  lines.push(bullets(parts.finalReport));
  return lines.join('\n');
}

export function buildAiFixPrompt(input: PromptInput): string {
  const fill = (text: string) => fillTemplate(text, input.ctx);
  const detail = sanitizeForPrompt(input.officialDetail);

  const intro: string[] = [];
  intro.push(`Supabaseプロジェクトの${input.ctx.target}について、Supabase Security Advisor で「${sanitizeForPrompt(input.advisorName, 100)}」の指摘が出ています。`);
  if (detail) intro.push(`Supabaseの指摘内容（英語）: ${detail}`);
  if (input.helpUrl) intro.push(`公式の解説: ${input.helpUrl}`);
  return composeFixPrompt({
    intro,
    task: fill(input.spec.task),
    checks: [...COMMON_CHECKS, ...(input.spec.extraChecks ?? [])].map(fill),
    rules: [...COMMON_RULES, ...(input.spec.extraRules ?? [])].map(fill),
    finalReport: FINAL_REPORT,
  });
}
