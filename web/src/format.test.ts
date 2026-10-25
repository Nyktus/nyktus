// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { expect, test } from 'vitest';
import { isolate } from './format';

test('isolate wraps a text in a first strong isolate, so that its direction stays inside it', () => {
  expect(isolate('Portal')).toBe('\u2068Portal\u2069');
  expect(isolate('\u05e9\u05dc\u05d5\u05dd').startsWith('\u2068')).toBe(true);
  expect(isolate('')).toBe('\u2068\u2069');
});
