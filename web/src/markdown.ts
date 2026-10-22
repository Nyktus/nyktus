// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * A small reader for the Markdown of the guides. It makes a tree of blocks and
 * inline parts that a component draws as elements, so that no text ever becomes
 * markup: HTML in the text stays text, and a link is only made for an address
 * with the scheme http or https.
 *
 * It reads what the guides use: headings, paragraphs, lists, code blocks, quotes,
 * code, emphasis and links. Everything else is a paragraph of text.
 */

export type Inline =
  | { kind: 'text'; text: string }
  | { kind: 'code'; text: string }
  | { kind: 'strong'; children: Inline[] }
  | { kind: 'em'; children: Inline[] }
  | { kind: 'link'; href: string; children: Inline[] };

/** An item of a list: its text, and the paragraphs and code blocks that stand indented below it. */
export interface ListItem {
  children: Inline[];
  blocks: Block[];
}

export type Block =
  | { kind: 'heading'; level: 1 | 2 | 3 | 4 | 5 | 6; children: Inline[] }
  | { kind: 'paragraph'; children: Inline[] }
  | { kind: 'list'; ordered: boolean; items: ListItem[] }
  | { kind: 'code'; text: string }
  | { kind: 'quote'; children: Inline[] };

const heading = /^(#{1,6})[ \t]+(.*)$/;
const bullet = /^[-*+]\s+(.*)$/;
const numbered = /^\d+[.)]\s+(.*)$/;
const fence = /^```/;
const quote = /^>\s?(.*)$/;

/**
 * The most that is read as Markdown. The guides are a few kilobytes; a longer text is shown
 * as it is, because the reader would take time in proportion to a text that it cannot
 * mean to read.
 */
export const maxSource = 64 * 1024;

const space = (c: string | undefined): boolean => c === ' ' || c === '\t';

/**
 * The text of a heading without the closing sequence of hashes, which only counts after a space
 * (so "Use C#" keeps its hash). It reads from the end and never looks back, so a line of
 * spaces cannot make it slow.
 */
function headingText(rest: string): string {
  let end = rest.length;
  while (end > 0 && space(rest[end - 1])) {
    end--;
  }
  let hashes = end;
  while (hashes > 0 && rest[hashes - 1] === '#') {
    hashes--;
  }
  if (hashes < end && (hashes === 0 || space(rest[hashes - 1]))) {
    end = hashes;
    while (end > 0 && space(rest[end - 1])) {
      end--;
    }
  }
  return rest.slice(0, end);
}

export function parseMarkdown(source: string): Block[] {
  if (source.length > maxSource) {
    return [{ kind: 'code', text: source }];
  }
  const lines = source.replace(/\r\n?/g, '\n').split('\n');
  const blocks: Block[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i] ?? '';
    if (line.trim() === '') {
      i++;
      continue;
    }

    if (fence.test(line)) {
      const body: string[] = [];
      i++;
      // A fence that is never closed runs to the end, as in most readers.
      while (i < lines.length && !fence.test(lines[i] ?? '')) {
        body.push(lines[i] ?? '');
        i++;
      }
      i++;
      blocks.push({ kind: 'code', text: body.join('\n') });
      continue;
    }

    const h = heading.exec(line);
    if (h) {
      blocks.push({ kind: 'heading', level: (h[1] ?? '#').length as 1 | 2 | 3 | 4 | 5 | 6, children: parseInline(headingText(h[2] ?? '')) });
      i++;
      continue;
    }

    const first = bullet.exec(line) ?? numbered.exec(line);
    if (first) {
      const ordered = numbered.test(line);
      interface Draft {
        text: string;
        blocks: ({ kind: 'code'; text: string } | { kind: 'paragraph'; text: string })[];
      }
      const items: Draft[] = [];
      let afterBlank = false;
      while (i < lines.length) {
        const current = lines[i] ?? '';
        const item = items[items.length - 1];
        if (current.trim() === '') {
          // A blank line stays inside the list if what follows is another item or is indented below one.
          let next = i + 1;
          while (next < lines.length && (lines[next] ?? '').trim() === '') {
            next++;
          }
          const following = lines[next] ?? '';
          if (item === undefined || next >= lines.length || !((ordered ? numbered : bullet).test(following) || /^\s{2,}\S/.test(following))) {
            break;
          }
          afterBlank = true;
          i = next;
          continue;
        }
        const match = (ordered ? numbered : bullet).exec(current);
        if (match) {
          items.push({ text: match[1] ?? '', blocks: [] });
          afterBlank = false;
        } else if (item !== undefined && /^\s{2,}```/.test(current)) {
          // A code block below an item, indented as the item is, belongs to it.
          const indent = current.length - current.trimStart().length;
          const body: string[] = [];
          i++;
          while (i < lines.length && !fence.test((lines[i] ?? '').trimStart())) {
            body.push((lines[i] ?? '').replace(new RegExp(`^ {0,${indent}}`), ''));
            i++;
          }
          item.blocks.push({ kind: 'code', text: body.join('\n') });
          afterBlank = false;
        } else if (item !== undefined && /^\s{2,}\S/.test(current)) {
          const last = item.blocks[item.blocks.length - 1];
          if (last?.kind === 'paragraph' && !afterBlank) {
            last.text += ' ' + current.trim();
          } else if (last === undefined && !afterBlank) {
            // A continuation line of the first line of the item.
            item.text += ' ' + current.trim();
          } else {
            item.blocks.push({ kind: 'paragraph', text: current.trim() });
          }
          afterBlank = false;
        } else {
          break;
        }
        i++;
      }
      blocks.push({
        kind: 'list',
        ordered,
        items: items.map((item) => ({
          children: parseInline(item.text),
          blocks: item.blocks.map((b): Block => (b.kind === 'code' ? b : { kind: 'paragraph', children: parseInline(b.text) })),
        })),
      });
      continue;
    }

    if (quote.test(line)) {
      const body: string[] = [];
      while (i < lines.length && quote.test(lines[i] ?? '')) {
        body.push(quote.exec(lines[i] ?? '')?.[1] ?? '');
        i++;
      }
      blocks.push({ kind: 'quote', children: parseInline(body.join(' ')) });
      continue;
    }

    const body: string[] = [];
    while (i < lines.length) {
      const current = lines[i] ?? '';
      if (current.trim() === '' || fence.test(current) || heading.test(current) || bullet.test(current) || numbered.test(current) || quote.test(current)) {
        break;
      }
      body.push(current.trim());
      i++;
    }
    blocks.push({ kind: 'paragraph', children: parseInline(body.join(' ')) });
  }
  return blocks;
}

/** The addresses that a link may have; anything else is shown as its text. */
function safeHref(href: string): string | undefined {
  if (/\s/.test(href)) {
    return undefined;
  }
  try {
    const url = new URL(href);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : undefined;
  } catch {
    return undefined;
  }
}

const code = /^`([^`]+)`/;
// The address may hold one level of parentheses, as in a link to a page of a wiki.
const link = /^\[([^\]]{1,500})\]\(([^()]{0,2000}(?:\([^()]{0,2000}\)[^()]{0,2000})*)\)/;
// Emphasis and code are looked for within a stretch of at most this many characters, so that
// many openers that never close cannot make every one of them read to the end of the text.
const reach = 500;
const strong = new RegExp(`^\\*\\*(?=\\S)(.{1,${reach}}?)(?<=\\S)\\*\\*`);
const emphasisStar = new RegExp(`^\\*(?=[^\\s*])(.{1,${reach}}?)(?<=[^\\s*])\\*`);
const emphasisUnderscore = new RegExp(`^_(?=[^\\s_])(.{1,${reach}}?)(?<=[^\\s_])_(?![A-Za-z0-9])`);

export function parseInline(text: string): Inline[] {
  const out: Inline[] = [];
  let plain = '';
  const flush = (): void => {
    if (plain !== '') {
      out.push({ kind: 'text', text: plain });
      plain = '';
    }
  };

  let i = 0;
  while (i < text.length) {
    const rest = text.slice(i);
    const previous = i > 0 ? (text[i - 1] ?? '') : '';
    let m: RegExpExecArray | null;
    if ((m = code.exec(rest))) {
      flush();
      out.push({ kind: 'code', text: m[1] ?? '' });
    } else if ((m = link.exec(rest))) {
      flush();
      const href = safeHref(m[2] ?? '');
      const children = parseInline(m[1] ?? '');
      if (href === undefined) {
        out.push(...children);
      } else {
        out.push({ kind: 'link', href, children });
      }
    } else if ((m = strong.exec(rest))) {
      flush();
      out.push({ kind: 'strong', children: parseInline(m[1] ?? '') });
    } else if ((m = emphasisStar.exec(rest))) {
      flush();
      out.push({ kind: 'em', children: parseInline(m[1] ?? '') });
    } else if (!/[A-Za-z0-9]/.test(previous) && (m = emphasisUnderscore.exec(rest))) {
      // An underscore inside a word, as in a name with underscores, is no emphasis.
      flush();
      out.push({ kind: 'em', children: parseInline(m[1] ?? '') });
    } else {
      plain += text[i] ?? '';
      i++;
      continue;
    }
    i += m[0].length;
  }
  flush();
  return out;
}
