// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, test } from 'vitest';
import { honeypotSlotQuery, honeytokenSlotQuery, readHoneypotPrefill, readHoneytokenPrefill } from './slotPrefill';

describe('the links of a slot', () => {
  test('a honeytoken slot names the scenario, the type, the label, the severity and the techniques', () => {
    const query = honeytokenSlotQuery('s1', { label: 'Database host', type: 'dns', techniques: ['T1552.001', 'T1078'], severity: 'high' });
    expect(query).toEqual({ scenario: 's1', type: 'dns', name: 'Database host', severity: 'high', techniques: 'T1552.001,T1078' });
    expect(readHoneytokenPrefill(query)).toEqual({
      name: 'Database host',
      severity: 'high',
      techniques: ['T1552.001', 'T1078'],
      type: 'dns',
    });
  });

  test('a slot without techniques leaves them out', () => {
    const query = honeytokenSlotQuery('s1', { label: 'Image', type: 'web_image', techniques: [], severity: 'low' });
    expect(query).not.toHaveProperty('techniques');
  });

  test('a honeypot slot names the scenario, the service and the label', () => {
    const query = honeypotSlotQuery('s1', { label: 'Database', service: 'postgres' });
    expect(query).toEqual({ scenario: 's1', service: 'postgres', name: 'Database' });
    expect(readHoneypotPrefill(query)).toEqual({ name: 'Database', service: 'postgres' });
  });
});

// The address is written by anyone who can send a link, so only what the form offers is taken over.
describe('what an address may fill in', () => {
  test.each([
    ['an unknown type', { type: 'script' }],
    ['a type in capitals', { type: 'DNS' }],
    ['a repeated type', { type: ['dns', 'web_url'] }],
    ['a service for a honeytoken', { service: 'ssh' }],
    ['an unknown severity', { severity: 'urgent' }],
    ['an empty name', { name: '' }],
    ['a name of spaces', { name: '   ' }],
    ['a name with a line break', { name: 'a\nb' }],
    ['a name with an invisible character', { name: 'a\u202Eb' }],
    ['a name beyond the limit', { name: 'x'.repeat(101) }],
    ['a repeated name', { name: ['a', 'b'] }],
    ['techniques that are none', { techniques: 'javascript:alert(1),<b>,T10,T1078.1' }],
  ])('a honeytoken drops %s', (_, query) => {
    expect(readHoneytokenPrefill(query)).toEqual({});
  });

  test('a honeypot drops a service it does not offer', () => {
    expect(readHoneypotPrefill({ service: 'telnetd' })).toEqual({});
    expect(readHoneypotPrefill({ service: 'mysql' })).toEqual({});
    expect(readHoneypotPrefill({ type: 'dns' })).toEqual({});
  });

  test('a name is kept as it is, markup included, because it only ever reaches a field', () => {
    expect(readHoneytokenPrefill({ name: '<img src=x onerror=alert(1)>' }).name).toBe('<img src=x onerror=alert(1)>');
  });

  test('techniques keep the valid ones, once each, and at most twenty', () => {
    expect(readHoneytokenPrefill({ techniques: 'T1078,x,T1078,T1003.001' }).techniques).toEqual(['T1078', 'T1003.001']);
    const many = Array.from({ length: 30 }, (_, i) => `T${String(1000 + i)}`).join(',');
    expect(readHoneypotPrefill({ techniques: many }).techniques).toHaveLength(20);
  });

  test('techniques are read like typed text, so a lower case identifier counts', () => {
    expect(readHoneytokenPrefill({ techniques: 't1078' }).techniques).toEqual(['T1078']);
  });

  test('a name at the limit is kept', () => {
    expect(readHoneypotPrefill({ name: 'x'.repeat(100) }).name).toHaveLength(100);
  });
});
