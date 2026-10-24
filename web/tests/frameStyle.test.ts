// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, test } from 'vitest';

// The DOM of the tests draws no styles, so the placement of the bar is read from the source.
const source = readFileSync(join(import.meta.dirname, '..', 'src', 'components', 'AppShell.vue'), 'utf8');

test('the account stays at the right edge of the bar on a wide screen, and under the logo on a narrow one', () => {
  expect(source).toMatch(/\.account \{[^}]*margin-left:\s*auto;/s);
  expect(source).toMatch(/@media \(max-width: 60rem\) \{[^@]*\.account \{[^}]*margin-left:\s*0;/s);
});

test('the list of the administration is hidden until it is opened, and stands open in the menu of a narrow screen', () => {
  expect(source).toMatch(/\.group-admin ul \{[^}]*display:\s*none;/s);
  expect(source).toMatch(/\.group-admin ul\.open \{\s*display:\s*flex;/);
  expect(source).toMatch(/@media \(max-width: 60rem\) \{[\s\S]*\.group-admin ul\.open \{[^}]*position:\s*static;[^}]*display:\s*flex;/);
});

test('the current page is filled with the light signal color and set in bold, with no line under it', () => {
  const rule = source.match(/nav a\.current,\s*\.admin-button\.current \{([^}]*)\}/s)?.[1] ?? '';
  expect(rule).toMatch(/background:\s*var\(--mint-soft\);/);
  expect(rule).toMatch(/font-weight:\s*700;/);
  expect(rule).not.toMatch(/box-shadow|border/);
});

test('a note keeps its distance from the panel, the table or the note that follows it', () => {
  const base = readFileSync(join(import.meta.dirname, '..', 'src', 'styles', 'base.css'), 'utf8');
  expect(base).toMatch(/\.notice \+ \.panel,\s*\.notice \+ \.table-wrap,\s*\.notice \+ \.notice \{\s*margin-top:\s*1rem;/);
});
