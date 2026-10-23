// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, test } from 'vitest';

// The DOM of the tests draws no styles, so the style that keeps attacker text from
// reordering its surroundings is read from the source.
test('the component isolates the direction of its text, wraps it and keeps its spaces', () => {
  const source = readFileSync(join(import.meta.dirname, '..', 'src', 'components', 'UntrustedText.vue'), 'utf8');
  expect(source).toMatch(/unicode-bidi:\s*isolate;/);
  expect(source).toMatch(/overflow-wrap:\s*anywhere;/);
  expect(source).toMatch(/white-space:\s*pre-wrap;/);
});
