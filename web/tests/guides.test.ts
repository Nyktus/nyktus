// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, test } from 'vitest';
import { parseMarkdown, type Block } from '../src/markdown';

const deceptions = join(import.meta.dirname, '..', '..', 'catalog', 'deceptions');

function guides(): [string, string][] {
  const out: [string, string][] = [];
  for (const name of readdirSync(deceptions, { recursive: true, encoding: 'utf8' })) {
    if (/(^|\/)guide\.[a-z]+\.md\.tmpl$/.test(name)) {
      out.push([name, readFileSync(join(deceptions, name), 'utf8')]);
    }
  }
  return out;
}

function texts(blocks: Block[]): string[] {
  return blocks.flatMap((b) => {
    switch (b.kind) {
      case 'code':
        return [];
      case 'list':
        return b.items.map((item) => JSON.stringify(item.children));
      default:
        return [JSON.stringify(b.children)];
    }
  });
}

// What the reader does not know turns into text, so a guide that uses it would show the marks of
// Markdown as they are. Every guide of the catalog is read, with the placeholders of its template.
test('every guide of the catalog is read, and shows no mark of a code block as text', () => {
  const all = guides();
  expect(all.length).toBeGreaterThan(0);
  for (const [name, source] of all) {
    expect(texts(parseMarkdown(source)).filter((t) => t.includes('```')), name).toEqual([]);
  }
});

test('the guide that writes a command below a step of a list keeps it as a code block of that step', () => {
  const source = readFileSync(join(deceptions, 'word-image', 'guide.en.md.tmpl'), 'utf8');
  const list = parseMarkdown(source).find((b) => b.kind === 'list' && b.items.some((item) => item.blocks.some((x) => x.kind === 'code')));
  expect(list).toBeDefined();
  expect(JSON.stringify(list)).toContain('INCLUDEPICTURE');
  const numbered = parseMarkdown(source).filter((b) => b.kind === 'list' && b.ordered);
  expect(numbered).toHaveLength(1);
});
