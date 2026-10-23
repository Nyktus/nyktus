// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { expect, test } from 'vitest';
import { parseTechniques } from './techniques';

test.each([
  ['', [], []],
  ['T1078', ['T1078'], []],
  ['t1078, T1003.001', ['T1078', 'T1003.001'], []],
  ['T1078 T1078\nT1003.001;T1021', ['T1078', 'T1003.001', 'T1021'], []],
  ['  T1078 ,, ', ['T1078'], []],
  ['T107', [], ['T107']],
  ['T1078.1, X1078, 1078, T1078.0001', [], ['T1078.1', 'X1078', '1078', 'T1078.0001']],
  ['T1078, nonsense', ['T1078'], ['nonsense']],
  ['T1078<script>', [], ['T1078<script>']],
])('parseTechniques(%j)', (text, ids, invalid) => {
  expect(parseTechniques(text)).toEqual({ ids, invalid });
});
