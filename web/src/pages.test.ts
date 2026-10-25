// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises } from '@vue/test-utils';
import { afterEach, expect, test, vi } from 'vitest';
import { navigation } from './navigation';
import { boot } from './testing/boot';
import { auditEntry, metricsText, plain, apiKey, userId, userRecord, alertChannel, alertDelivery, artifact, artifactId, catalogDeception, catalogSummary, event, eventId, fakeServer, honeypot, honeypotId, honeytoken, incident, incidentId, joined, json, scenario, scenarioId, sessionBody } from './testing/fakeServer';

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = '';
  history.replaceState(null, '', '/');
});

const htId = 'c0ffee00-1111-4222-8333-944444444444';

function server() {
  return fakeServer({
    'GET /api/v1/session': () => json(200, sessionBody('admin')),
    'GET /api/v1/honeytokens': () => json(200, { honeytokens: [honeytoken()] }),
    [`GET /api/v1/honeytokens/${htId}`]: () => json(200, honeytoken()),
    'GET /api/v1/honeypots': () => json(200, { honeypots: [honeypot()] }),
    [`GET /api/v1/honeypots/${honeypotId}`]: () => json(200, honeypot()),
    'GET /api/v1/scenarios': () => json(200, { scenarios: [scenario()] }),
    [`GET /api/v1/scenarios/${scenarioId}`]: () => json(200, scenario({ deceptions: [joined('browser-bookmarks')] })),
    [`GET /api/v1/scenarios/${scenarioId}/guide`]: () => json(200, { guides: [{ deception_id: 'browser-bookmarks', language: 'en', content: '# Guide' }] }),
    'GET /api/v1/catalog/deceptions': () => json(200, { deceptions: [catalogSummary()] }),
    'GET /api/v1/artifacts': () => json(200, { artifacts: [artifact()] }),
    [`GET /api/v1/artifacts/${artifactId}`]: () => json(200, artifact()),
    'GET /api/v1/catalog/deceptions/browser-bookmarks': () => json(200, catalogDeception()),
    'GET /api/v1/alert-channels': () => json(200, { alert_channels: [alertChannel()] }),
    [`GET /api/v1/alert-channels/${alertChannel().id}`]: () => json(200, alertChannel()),
    [`GET /api/v1/incidents/${incidentId}/deliveries`]: () => json(200, { deliveries: [alertDelivery()] }),
    'GET /api/v1/audit-entries': () => json(200, { entries: [auditEntry()] }),
    'GET /api/v1/metrics': () => plain(200, metricsText),
    'GET /api/v1/api-keys': () => json(200, { api_keys: [apiKey()] }),
    'GET /api/v1/users': () => json(200, { users: [userRecord()] }),
    [`GET /api/v1/users/${userId}`]: () => json(200, userRecord()),
    'GET /api/v1/incidents': () => json(200, { incidents: [incident()] }),
    [`GET /api/v1/incidents/${incidentId}`]: () => json(200, incident()),
    'GET /api/v1/events': () => json(200, { events: [event()] }),
    [`GET /api/v1/events/${eventId}`]: () => json(200, event()),
  });
}

// An id names one element of the page: a label, a hint and a script find it by it, so a second
// element with the same id breaks them without any sign.
test.each([
  '/',
  '/honeytokens',
  '/honeytokens/new',
  `/honeytokens/${htId}`,
  '/honeypots',
  '/honeypots/new',
  `/honeypots/${honeypotId}`,
  '/scenarios',
  '/scenarios/new',
  `/scenarios/${scenarioId}`,
  '/incidents',
  `/incidents/${incidentId}`,
  `/events/${eventId}`,
  '/alert-channels',
  '/alert-channels/new',
  `/alert-channels/${alertChannel().id}`,
  '/api-keys',
  '/api-keys/new',
  '/audit',
  '/metrics',
  '/users',
  '/users/new',
  `/users/${userId}`,
  '/artifacts',
  `/artifacts/${artifactId}`,
  '/catalog',
  '/catalog/browser-bookmarks',
  '/account',
  '/forbidden',
])('%s has no id twice, and every label points at a field', async (path) => {
  const { wrapper } = await boot(server(), path);
  const ids = [...document.body.querySelectorAll('[id]')].map((e) => e.id);
  expect(ids.filter((id, i) => ids.indexOf(id) !== i), 'ids that are used twice').toEqual([]);
  for (const label of wrapper.findAll('label[for]')) {
    expect(document.getElementById(label.attributes('for') ?? ''), `the target of the label "${label.text()}"`).not.toBeNull();
  }
  for (const element of wrapper.findAll('[aria-describedby]')) {
    for (const target of (element.attributes('aria-describedby') ?? '').split(' ')) {
      expect(document.getElementById(target), `the description ${target}`).not.toBeNull();
    }
  }
});

// The pages of the sign-in and of the links of the server need no session, and have the same
// duty: no id twice, every label at a field.
test.each(['/sign-in', '/setup', '/activate', '/reset-password'])('%s has no id twice, and every label points at a field', async (path) => {
  const signedOut = fakeServer({
    'GET /api/v1/session': () => json(401, { error: { code: 'unauthenticated', message: 'x' } }),
    'GET /api/v1/sign-in-options': () => json(200, { password: true, oidc: 'available' }),
  });
  const { wrapper } = await boot(signedOut, path);
  expect(wrapper.find('input').exists() || wrapper.find('h1').exists()).toBe(true);
  const ids = [...document.body.querySelectorAll('[id]')].map((e) => e.id);
  expect(ids.filter((id, i) => ids.indexOf(id) !== i), 'ids that are used twice').toEqual([]);
  for (const label of wrapper.findAll('label[for]')) {
    expect(document.getElementById(label.attributes('for') ?? ''), `the target of the label "${label.text()}"`).not.toBeNull();
  }
  for (const element of wrapper.findAll('[aria-describedby]')) {
    for (const target of (element.attributes('aria-describedby') ?? '').split(' ')) {
      expect(document.getElementById(target), `the description ${target}`).not.toBeNull();
    }
  }
});

// Every page of the navigation points to the documentation instead of explaining itself, and the
// link opens a new tab, so that the console stays where it is.
const menuPages = ['/', '/incidents', '/honeytokens', '/honeypots', '/scenarios', '/artifacts', '/catalog', '/alert-channels', '/users', '/api-keys', '/audit', '/metrics'];

test('the list of pages with a link to the documentation is the navigation', () => {
  expect(menuPages).toHaveLength(navigation.length);
});

test.each(menuPages)('%s links to the documentation under its title, and opens it in a new tab', async (path) => {
  const { wrapper } = await boot(server(), path);
  const links = wrapper.findAll('main a[href="https://docs.nyktus.org"]');
  expect(links).toHaveLength(1);
  expect(links[0]!.attributes('target')).toBe('_blank');
  expect(links[0]!.attributes('rel')).toBe('noopener noreferrer');
  expect(links[0]!.text()).toBe('More in the documentation (opens in a new tab)');
  expect(wrapper.get('.page-head').element.contains(links[0]!.element)).toBe(true);
});

test('the link to the documentation is in German as well', async () => {
  const { wrapper, i18n } = await boot(server(), '/incidents');
  i18n.setLocale('de');
  await flushPromises();
  expect(wrapper.get('main a[href="https://docs.nyktus.org"]').text()).toBe('Mehr dazu in der Dokumentation (öffnet in einem neuen Tab)');
});
