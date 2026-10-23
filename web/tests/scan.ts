// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

export interface Rule {
  name: string;
  pattern: RegExp;
  /** The rule holds if this matches within `window` lines around the line of the match. */
  unless?: RegExp;
  window?: number;
  /** Files, by path below src, that may break the rule, with the reason. */
  allowed?: Record<string, string>;
}

/**
 * The rules of the web console that a type check does not enforce. A rule is
 * only as good as the proof that it fires: scan.test.ts breaks each one on
 * purpose.
 */
export const rules: Rule[] = [
  { name: 'v-html renders text as markup', pattern: /\bv-html\b/ },
  { name: 'innerHTML renders text as markup', pattern: /\binnerHTML\b/ },
  { name: 'outerHTML renders text as markup', pattern: /\bouterHTML\b/ },
  { name: 'insertAdjacentHTML renders text as markup', pattern: /\binsertAdjacentHTML\b/ },
  { name: 'document.write renders text as markup', pattern: /\bdocument\s*\.\s*write(ln)?\s*\(/ },
  { name: 'eval runs text as code', pattern: /\beval\s*\(/ },
  { name: 'new Function runs text as code', pattern: /\bnew\s+Function\b/ },
  { name: 'a string timer runs text as code', pattern: /\bset(Timeout|Interval)\s*\(\s*['"`]/ },
  {
    name: 'localStorage outlives the session and is read by every script of the origin',
    pattern: /\blocalStorage\b/,
    allowed: {},
  },
  { name: 'sessionStorage is read by every script of the origin', pattern: /\bsessionStorage\b/ },
  { name: 'indexedDB is read by every script of the origin', pattern: /\bindexedDB\b/ },
  {
    name: 'requests go through the client, which maps their errors',
    pattern: /\bfetch\s*\(/,
    allowed: {},
  },
  { name: 'XMLHttpRequest bypasses the client', pattern: /\bXMLHttpRequest\b/ },
  { name: 'WebSocket is not part of the API', pattern: /\bWebSocket\b/ },
  { name: 'EventSource is not part of the API', pattern: /\bEventSource\b/ },
  { name: 'sendBeacon sends data without the client', pattern: /\bsendBeacon\b/ },
  { name: 'the console loads nothing from another origin', pattern: /https?:\/\//, allowed: {} },
  {
    // A template names it as an attribute, a render function as a member; the
    // attributes of an element stand on several lines, in either order.
    name: 'a link that opens a window needs rel="noopener noreferrer"',
    pattern: /target\s*[=:]\s*["']_blank["']/,
    unless: /rel\s*[=:]\s*["'](?=[^"']*\bnoopener\b)(?=[^"']*\bnoreferrer\b)[^"']*["']/,
    window: 3,
  },
];

export interface Violation {
  file: string;
  line: number;
  rule: string;
}

/** Returns where the files, by path below src, break a rule. */
export function scan(files: Record<string, string>): Violation[] {
  const out: Violation[] = [];
  for (const [file, text] of Object.entries(files)) {
    const lines = text.split('\n');
    lines.forEach((content, i) => {
      for (const rule of rules) {
        if (!rule.pattern.test(content) || (rule.allowed && file in rule.allowed)) {
          continue;
        }
        const near = lines.slice(Math.max(0, i - (rule.window ?? 0)), i + (rule.window ?? 0) + 1).join('\n');
        if (!(rule.unless && rule.unless.test(near))) {
          out.push({ file, line: i + 1, rule: rule.name });
        }
      }
    });
  }
  return out;
}
