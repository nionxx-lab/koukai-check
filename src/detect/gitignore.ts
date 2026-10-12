// .gitignore の簡易判定。.env 系のファイルが Git の管理対象から外れているかを調べるためだけに使う。
// 完全な gitignore の実装ではない（否定パターン「!」とよく使われる書き方に対応する程度）。

function patternToRegExp(pattern: string): RegExp {
  let p = pattern.trim();
  const anchored = p.startsWith('/');
  if (anchored) p = p.slice(1);
  if (p.endsWith('/')) p = p.slice(0, -1);
  const body = p
    .split('')
    .map((ch) => {
      if (ch === '*') return '[^/]*';
      if (ch === '?') return '[^/]';
      return ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    })
    .join('')
    .replace(/\[\^\/\]\*\[\^\/\]\*/g, '.*'); // **
  return anchored || p.includes('/') ? new RegExp(`^${body}$`) : new RegExp(`(^|/)${body}$`);
}

export interface GitignoreRules {
  /** dirOnly：末尾が / のパターン（フォルダにだけ当てはまる） */
  patterns: { re: RegExp; negate: boolean; dirOnly: boolean }[];
}

export function parseGitignore(text: string): GitignoreRules {
  const patterns: GitignoreRules['patterns'] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const negate = line.startsWith('!');
    const body = negate ? line.slice(1) : line;
    patterns.push({ re: patternToRegExp(body), negate, dirOnly: body.endsWith('/') });
  }
  return { patterns };
}

/** 1つのパス（ファイルかフォルダ）が、ルールの上で無視されるか */
function matches(relativePath: string, isDir: boolean, rulesList: { base: string; rules: GitignoreRules }[]): boolean {
  let ignored = false;
  for (const { base, rules } of rulesList) {
    const prefix = base ? `${base}/` : '';
    if (base && !relativePath.startsWith(prefix)) continue;
    const rel = relativePath.slice(prefix.length);
    for (const { re, negate, dirOnly } of rules.patterns) {
      if (dirOnly && !isDir) continue;
      if (re.test(rel)) ignored = !negate;
    }
  }
  return ignored;
}

/**
 * relativePath（区切りは /）が無視されるか。
 * rules は「そのパスに近いものほど後ろ」になるように並べて渡す（後のルールが優先）。
 * 親のフォルダが無視されていれば、その中のファイルも無視される（Git と同じく、中のファイルを「!」で戻すことはできない）。
 * 例：`test-results/` と書かれていれば、`test-results/claude-runner-canary.json` も無視される。
 */
export function isIgnored(relativePath: string, rulesList: { base: string; rules: GitignoreRules }[]): boolean {
  const parts = relativePath.split('/');
  for (let i = 1; i < parts.length; i++) {
    if (matches(parts.slice(0, i).join('/'), true, rulesList)) return true;
  }
  return matches(relativePath, false, rulesList);
}
