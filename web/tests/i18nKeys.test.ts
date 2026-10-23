// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, test } from 'vitest';
import { de } from '../src/i18n/de';
import { en } from '../src/i18n/en';

const src = join(import.meta.dirname, '..', 'src');

function sources(): string {
  const parts: string[] = [];
  for (const name of readdirSync(src, { recursive: true, encoding: 'utf8' })) {
    if (/\.(ts|vue)$/.test(name) && !name.endsWith('.test.ts') && !name.startsWith('i18n/') && !name.startsWith('testing/') && !name.endsWith('generated.ts')) {
      parts.push(readFileSync(join(src, name), 'utf8'));
    }
  }
  return parts.join('\n');
}

// A text that nothing shows is a text that has to be kept in two languages for nothing.
test('every text of the catalog is used, by its key or by the start of a key that is put together', () => {
  const code = sources();
  const prefixes = [...code.matchAll(/[`'"]([A-Za-z0-9_.]+\.)\$\{/g)].map((m) => m[1] ?? '');
  const unused = Object.keys(en).filter((key) => !code.includes(`'${key}'`) && !code.includes(`"${key}"`) && !code.includes(`\`${key}\``) && !prefixes.some((p) => key.startsWith(p)));
  expect(unused).toEqual([]);
});

test('both languages have the same keys', () => {
  expect(Object.keys(de).sort()).toEqual(Object.keys(en).sort());
});
