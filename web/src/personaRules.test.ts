// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, test } from 'vitest';
import { checkPersonaValue, personaProblems, personaToSend, type PersonaField, type PersonaKind, type PersonaProblem } from './personaRules';

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

describe('the values of a persona', () => {
  const fields: PersonaField[] = [
    { key: 'company', kind: 'text', label: 'Company', example: 'Acme Corp' },
    { key: 'host', kind: 'host', label: 'Host', example: 'jump02' },
  ];

  test('are checked by key, and a key the scenario has is not checked', () => {
    expect(personaProblems(fields, { company: '', host: 'Jump_02' })).toEqual({ company: 'required', host: 'host' });
    expect(personaProblems(fields, { company: '', host: 'jump02' }, { company: 'Acme Corp' })).toEqual({});
    expect(personaProblems(fields, {}, { company: 'Acme Corp' })).toEqual({ host: 'required' });
  });

  test('are sent trimmed, and without the keys the scenario has', () => {
    expect(personaToSend(fields, { company: ' Acme Corp ', host: ' jump02 ' })).toEqual({ company: 'Acme Corp', host: 'jump02' });
    expect(personaToSend(fields, { company: 'Other', host: ' jump02 ' }, { company: 'Acme Corp' })).toEqual({ host: 'jump02' });
  });

  test('treat a key as there even when its value is empty', () => {
    expect(personaToSend(fields, { host: 'a' }, { company: '' })).toEqual({ host: 'a' });
  });
});
