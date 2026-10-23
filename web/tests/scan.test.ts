// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { attackerFields, rules, scan } from './scan';

const src = join(import.meta.dirname, '..', 'src');

function sources(): Record<string, string> {
  const files: Record<string, string> = {};
  for (const name of readdirSync(src, { recursive: true, encoding: 'utf8' })) {
    // The tests name the constructs that the rules forbid, the helpers of the tests
    // clear the storage, and the generated types hold the paths of the API.
    const test = name.endsWith('.test.ts') || name.startsWith('testing/') || name.endsWith('generated.ts');
    if (/\.(ts|vue)$/.test(name) && !test) {
      files[name] = readFileSync(join(src, name), 'utf8');
    }
  }
  return files;
}

test('the sources break no rule of the web console', () => {
  const files = sources();
  expect(Object.keys(files)).toContain('main.ts');
  expect(scan(files)).toEqual([]);
});

// A rule that never fires protects nothing, so each one is broken on purpose.
describe('every rule fires on a violation', () => {
  const violations: Record<string, string> = {
    'v-html renders text as markup': '<div v-html="text"></div>',
    'innerHTML renders text as markup': 'el.innerHTML = text;',
    'outerHTML renders text as markup': 'el.outerHTML = text;',
    'insertAdjacentHTML renders text as markup': "el.insertAdjacentHTML('beforeend', text);",
    'document.write renders text as markup': 'document.write(text);',
    'eval runs text as code': 'eval(text);',
    'new Function runs text as code': "new Function('return 1');",
    'a string timer runs text as code': "setTimeout('run()', 10);",
    'localStorage outlives the session and is read by every script of the origin': "localStorage.setItem('a', 'b');",
    'sessionStorage is read by every script of the origin': "sessionStorage.getItem('a');",
    'indexedDB is read by every script of the origin': "indexedDB.open('a');",
    'requests go through the client, which maps their errors': "await fetch('/api/v1/session');",
    'XMLHttpRequest bypasses the client': 'new XMLHttpRequest();',
    'WebSocket is not part of the API': "new WebSocket('wss://a');",
    'EventSource is not part of the API': "new EventSource('/events');",
    'sendBeacon sends data without the client': "navigator.sendBeacon('/a', data);",
    'the console loads nothing from another origin': "import('https://cdn.example.com/a.js');",
    'text that an attacker sent is shown only by UntrustedText': '<td>{{ event.http.user_agent }}</td>',
    'text that an attacker sent is not taken out of its object by name': 'const { username } = attempt;',
    'a link that opens a window needs rel="noopener noreferrer"': '<a href="/x" target="_blank">x</a>',
  };

  test('the table names every rule', () => {
    expect(Object.keys(violations).sort()).toEqual(rules.map((r) => r.name).sort());
  });

  for (const [rule, code] of Object.entries(violations)) {
    test(rule, () => {
      expect(scan({ 'a.ts': code }).map((v) => v.rule)).toContain(rule);
    });
  }

  test('a field handed to UntrustedText passes, and so does the key of a text', () => {
    expect(scan({ 'a.vue': '<dd><UntrustedText :value="event.http.user_agent" /></dd>' })).toEqual([]);
    expect(scan({ 'a.ts': "'event.database': 'Database'," })).toEqual([]);
    expect(scan({ 'a.vue': "{{ t('event.database') }}" })).toEqual([]);
    expect(scan({ 'a.ts': 'items.filter((i) => i.ok);' })).toEqual([]);
    expect(scan({ 'a.vue': '<template v-if="event.sensor.database !== null">' })).toEqual([]);
  });

  test.each(attackerFields)('the field %s is found outside UntrustedText, and not inside', (field) => {
    expect(scan({ 'a.vue': `<td>{{ row.${field} }}</td>` }).map((v) => v.rule)).toContain('text that an attacker sent is shown only by UntrustedText');
    expect(scan({ 'a.vue': `<td><UntrustedText :value="row.${field}" /></td>` })).toEqual([]);
  });

  test('a second field on the line of a first, which is handed over, is found', () => {
    expect(scan({ 'a.vue': '<dd><UntrustedText :value="e.http.user_agent" /> {{ e.http.referer }}</dd>' }).map((v) => v.rule)).toContain(
      'text that an attacker sent is shown only by UntrustedText',
    );
    expect(scan({ 'a.vue': '<dd><UntrustedText :value="e.http.user_agent" /><UntrustedText :value="e.http.referer" /></dd>' })).toEqual([]);
  });

  test.each([
    'const { username } = attempt;',
    'const { id, key_fingerprint, other } = attempt;',
    'attempts.map(({ key_fingerprint }) => key_fingerprint);',
    '<tr v-for="{ filter } in rows">',
    'const user = event.http["user_agent"];',
    "const user = event.http[ 'user_agent' ];",
  ])('a field that is taken out of its object by name fails: %s', (code) => {
    expect(scan({ 'a.vue': code }).map((v) => v.rule)).toContain('text that an attacker sent is not taken out of its object by name');
  });

  test.each(['const { user, role } = session;', 'api.call(x, { body: { email, password } });', 'const filterAll = 1;', 'items.filter((i) => i.ok);', 'groups.map((group) => ({ group, items: usable.filter((item) => item.group === group) }));'])(
    'what is not a field of an attacker passes: %s',
    (code) => {
      expect(scan({ 'a.ts': code })).toEqual([]);
    },
  );

  test.each(['{{ event.sensor.database }}', ':title="attempt.username"', 'const name = event.dns.prefix;', 'show(event.sensor.query.filter)'])(
    'a field outside UntrustedText fails: %s',
    (code) => {
      expect(scan({ 'a.vue': code }).map((v) => v.rule)).toContain('text that an attacker sent is shown only by UntrustedText');
    },
  );

  test('a link with rel passes', () => {
    expect(scan({ 'a.vue': '<a href="/x" target="_blank" rel="noopener noreferrer">x</a>' })).toEqual([]);
  });

  const rule = 'a link that opens a window needs rel="noopener noreferrer"';

  test('a link passes with rel before target, on other lines, or as a member of a render function', () => {
    expect(scan({ 'a.vue': '<a rel="noopener noreferrer" target="_blank">x</a>' })).toEqual([]);
    expect(scan({ 'a.vue': '<a\n  href="/x"\n  target="_blank"\n  rel="noreferrer noopener"\n>x</a>' })).toEqual([]);
    expect(scan({ 'a.ts': "h('a', { href, target: '_blank', rel: 'noopener noreferrer' }, text);" })).toEqual([]);
  });

  test.each([
    ["h('a', { href, target: '_blank' }, text);", 'a member of a render function without rel'],
    ['<a\n  href="/x"\n  target="_blank"\n>x</a>', 'attributes on several lines without rel'],
    ['<a target="_blank" rel="noopener">x</a>', 'rel without noreferrer'],
    ['<a target="_blank" rel="noreferrer">x</a>', 'rel without noopener'],
    ['<a target="_blank">x</a>\n\n\n\n<a rel="noopener noreferrer">y</a>', 'a rel of another element, out of reach'],
  ])('a link fails: %s (%s)', (code) => {
    expect(scan({ 'a.vue': code }).map((v) => v.rule)).toContain(rule);
  });
});
