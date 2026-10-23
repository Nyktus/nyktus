// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, test } from 'vitest';

// The DOM of the tests draws no styles, so the placement of the bar is read from the source.
test('the account stays at the right edge of the bar on a wide screen, and under the logo on a narrow one', () => {
  const source = readFileSync(join(import.meta.dirname, '..', 'src', 'components', 'AppShell.vue'), 'utf8');
  expect(source).toMatch(/\.account \{[^}]*margin-left:\s*auto;/s);
  expect(source).toMatch(/@media \(max-width: 52rem\) \{\s*\.account \{\s*margin-left:\s*0;/);
});
