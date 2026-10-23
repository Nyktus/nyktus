// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, test } from 'vitest';
import { attackerFields } from './scan';

// The rule that attacker text is shown by one component only knows the fields in its list. A text
// member that the specification adds to these types, and that nobody added to the list, is shown
// without the component until this test says so.
const types = ['EventRequest', 'EventSession', 'EventAttempt', 'EventQuery', 'EventSessionQuery'];

function textMembers(source: string, type: string): string[] {
  const body = new RegExp(`export interface ${type} \\{(.*?)\\n\\}`, 's').exec(source)?.[1];
  expect(body, `the type ${type} in the generated types`).toBeDefined();
  return [...(body ?? '').matchAll(/^\s+(\w+)\??: ([^;]+);$/gm)]
    .filter(([, , type]) => /\bstring\b/.test(type ?? '') && !/'/.test(type ?? ''))
    .map(([, name]) => name ?? '');
}

test('every text member of the events of an attacker is in the list of the rule', () => {
  const source = readFileSync(join(import.meta.dirname, '..', 'src', 'api', 'generated.ts'), 'utf8');
  const found = types.flatMap((type) => textMembers(source, type)).sort();
  expect(found).toEqual([...attackerFields].sort());
});
