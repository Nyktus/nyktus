// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { expect, test } from 'vitest';
import { checkPersonaValue, type PersonaKind, type PersonaProblem } from './personaRules';

test.each<[PersonaKind, string, PersonaProblem | undefined]>([
  ['host', 'jump02', undefined],
  ['host', 'jump02.corp.example.com', undefined],
  ['host', 'a', undefined],
  ['host', 'a-b.c', undefined],
  ['host', '', 'required'],
  ['host', '   ', 'required'],
  ['host', 'Jump02', 'host'],
  ['host', 'jump_02', 'host'],
  ['host', '-jump', 'host'],
  ['host', 'jump.', 'host'],
  ['host', 'jump 02', 'host'],
  ['host', 'https://jump', 'host'],
  ['name', 'svc-backup', undefined],
  ['name', '', 'required'],
  ['text', 'Acme Corp', undefined],
  ['text', 'x'.repeat(200), undefined],
  ['text', 'x'.repeat(201), 'text'],
  ['text', 'two\nlines', 'text'],
  ['text', 'carriage\rreturn', 'text'],
  ['text', '', 'required'],
  ['host', ' jump02 ', undefined],
  ['host', '\tjump02\n', undefined],
  ['text', `${'x'.repeat(200)} `, undefined],
  ['text', 'a\nb', 'text'],
  ['text', '\u{1F600}'.repeat(200), undefined],
  ['text', '\u{1F600}'.repeat(201), 'text'],
  ['text', `\u00e9${'x'.repeat(199)}`, undefined],
])('checkPersonaValue(%s, %j) = %s', (kind, value, want) => {
  expect(checkPersonaValue(kind, value)).toBe(want);
});
