// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

export interface Rule {
  name: string;
  pattern: RegExp;
  /** Text that is cut from a line before the pattern is tried, such as quoted keys of texts. */
  strip?: RegExp;
  /** A match of the pattern inside a match of this is no violation, such as a field handed to its component. */
  within?: RegExp;
  /** The rule holds if this matches within `window` lines around the line of the match. */
  unless?: RegExp;
  window?: number;
  /** Files, by path below src, that may break the rule, with the reason. */
  allowed?: Record<string, string>;
}

/**
 * What an attacker chooses in the events of the console: the headers of a request, what a
 * session sent and asked for, the name that a query asked for. A test compares the list with the
 * text members of these types in the specification.
 */
export const attackerFields = [
  'user_agent',
  'referer',
  'accept_language',
  'client_version',
  'database',
  'application_name',
  'username',
  'key_fingerprint',
  'zone',
  'prefix',
  'qtype',
  'base_dn',
  'filter',
] as const;

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
    allowed: { 'i18n/preference.ts': 'it keeps the language the user chose, which is neither a secret nor a credential' },
  },
  { name: 'sessionStorage is read by every script of the origin', pattern: /\bsessionStorage\b/ },
  { name: 'indexedDB is read by every script of the origin', pattern: /\bindexedDB\b/ },
  {
    name: 'requests go through the client, which maps their errors',
    pattern: /\bfetch\s*\(/,
    allowed: { 'api/client.ts': 'it is the client' },
  },
  { name: 'XMLHttpRequest bypasses the client', pattern: /\bXMLHttpRequest\b/ },
  { name: 'WebSocket is not part of the API', pattern: /\bWebSocket\b/ },
  { name: 'EventSource is not part of the API', pattern: /\bEventSource\b/ },
  { name: 'sendBeacon sends data without the client', pattern: /\bsendBeacon\b/ },
  {
    name: 'the console loads nothing from another origin',
    pattern: /https?:\/\//,
    allowed: { 'docs.ts': 'it names the documentation, which only a link that the user follows opens' },
  },
  {
    // Text that an attacker sent is drawn by one component, which isolates its direction
    // and shows the characters that draw nothing. Every place that names such a field must
    // hand it to that component. The keys of texts, in single quotes, are not fields, and
    // asking whether a member is there shows nothing.
    name: 'text that an attacker sent is shown only by UntrustedText',
    strip: /'[^']*'/g,
    pattern: new RegExp(`\\.(${attackerFields.join('|')})\\b(?!\\(|\\s*[!=]==\\s*null)`),
    within: /<UntrustedText\b[^>]*>/,
  },
  {
    // A rule that looks for `.user_agent` cannot see a field that was taken out of its object.
    name: 'text that an attacker sent is not taken out of its object by name',
    pattern: new RegExp(
      `\\{[\\w$\\s,:]*\\b(${attackerFields.join('|')})\\b[\\w$\\s,:]*\\}\\s*(?:=[^=>]|\\)|in\\s|of\\s)|\\[\\s*['"](${attackerFields.join('|')})['"]\\s*\\]`,
    ),
  },
  {
    // A template names it as an attribute, a render function as a member; the
    // attributes of an element stand on several lines, in either order.
    name: 'a link that opens a window needs rel="noopener noreferrer"',
    pattern: /target\s*[=:]\s*["']_blank["']/,
    unless: /rel\s*[=:]\s*["'](?=[^"']*\bnoopener\b)(?=[^"']*\bnoreferrer\b)[^"']*["']/,
    window: 3,
  },
];

const everywhere = (pattern: RegExp): RegExp => new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`);

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
        if (rule.allowed && file in rule.allowed) {
          continue;
        }
        const seen = rule.strip ? content.replace(rule.strip, "''") : content;
        const spans = rule.within ? [...seen.matchAll(everywhere(rule.within))].map((m) => [m.index, m.index + m[0].length] as const) : [];
        const outside = [...seen.matchAll(everywhere(rule.pattern))].filter((m) => !spans.some(([from, to]) => m.index >= from && m.index < to));
        const near = lines.slice(Math.max(0, i - (rule.window ?? 0)), i + (rule.window ?? 0) + 1).join('\n');
        if (outside.length > 0 && !(rule.unless && rule.unless.test(near))) {
          out.push({ file, line: i + 1, rule: rule.name });
        }
      }
    });
  }
  return out;
}
