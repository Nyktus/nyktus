// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, test } from 'vitest';
import { honeypotSlotQuery, honeytokenSlotQuery, readHoneypotPrefill, readHoneytokenPrefill } from '../src/slotPrefill';

const deceptions = join(import.meta.dirname, '..', '..', 'catalog', 'deceptions');

interface Slots {
  honeytokens: { label: Record<string, string>; type: 'web_url' | 'web_image' | 'dns'; techniques?: string[]; severity?: 'low' | 'medium' | 'high' | 'critical' }[];
  honeypots: { label: Record<string, string>; service: 'ssh' | 'telnet' | 'postgres' | 'ldap' }[];
}

function entries(): [string, Slots][] {
  return readdirSync(deceptions, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry): [string, Slots] => [entry.name, JSON.parse(readFileSync(join(deceptions, entry.name, 'deception.json'), 'utf8')) as Slots]);
}

// The link of a slot carries the label as a name and the form takes it over only if it looks like a name. The catalog
// checks a label as a name when it loads, so no label may be one that the form would drop.
test('the form takes over the label, the type and the techniques of every slot of the catalog', () => {
  const all = entries();
  expect(all.length).toBeGreaterThan(0);
  for (const [id, slots] of all) {
    for (const lang of ['en', 'de']) {
      for (const slot of slots.honeytokens) {
        const label = slot.label[lang] ?? '';
        const query = honeytokenSlotQuery('s', { label, type: slot.type, techniques: slot.techniques ?? [], severity: slot.severity ?? 'medium' });
        const found = readHoneytokenPrefill(query);
        expect(found.name, `${id} ${lang} ${label}`).toBe(label);
        expect(found.type, id).toBe(slot.type);
        expect(found.techniques ?? [], id).toEqual(slot.techniques ?? []);
      }
      for (const slot of slots.honeypots) {
        const label = slot.label[lang] ?? '';
        const found = readHoneypotPrefill(honeypotSlotQuery('s', { label, service: slot.service }));
        expect(found.name, `${id} ${lang} ${label}`).toBe(label);
        expect(found.service, id).toBe(slot.service);
      }
    }
  }
});
