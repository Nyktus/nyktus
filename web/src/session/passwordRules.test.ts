// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { expect, test } from 'vitest';
import { checkNewPassword } from './passwordRules';

test.each([
  ['a'.repeat(11), 'a'.repeat(11), 'too_short'],
  ['a'.repeat(12), 'a'.repeat(12), undefined],
  ['a'.repeat(128), 'a'.repeat(128), undefined],
  ['a'.repeat(129), 'a'.repeat(129), 'too_long'],
  ['a'.repeat(12), 'a'.repeat(11) + 'b', 'mismatch'],
  // Characters, not bytes or UTF-16 units: twelve of these are twelve code points.
  ['\u00e4'.repeat(12), '\u00e4'.repeat(12), undefined],
  ['\u{1F512}'.repeat(12), '\u{1F512}'.repeat(12), undefined],
  ['\u{1F512}'.repeat(11), '\u{1F512}'.repeat(11), 'too_short'],
  ['\u{1F512}'.repeat(128), '\u{1F512}'.repeat(128), undefined],
  // The same password typed on different systems: a + combining diaeresis is one character after normalization.
  ['a\u0308'.repeat(12), 'a\u0308'.repeat(12), undefined],
  ['a\u0308'.repeat(11), 'a\u0308'.repeat(11), 'too_short'],
])('checkNewPassword(%j, %j) = %s', (password, repetition, want) => {
  expect(checkNewPassword(password, repetition)).toBe(want);
});
