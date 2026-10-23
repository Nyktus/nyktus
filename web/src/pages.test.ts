// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { afterEach, expect, test, vi } from 'vitest';
import { boot } from './testing/boot';
import { artifact, artifactId, catalogDeception, catalogSummary, fakeServer, honeypot, honeypotId, honeytoken, json, scenario, scenarioId, sessionBody } from './testing/fakeServer';

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
    [`GET /api/v1/scenarios/${scenarioId}`]: () => json(200, scenario({ deception_id: 'browser-bookmarks', language: 'en' })),
    [`GET /api/v1/scenarios/${scenarioId}/guide`]: () => json(200, { language: 'en', content: '# Guide' }),
    'GET /api/v1/catalog/deceptions': () => json(200, { deceptions: [catalogSummary()] }),
    'GET /api/v1/artifacts': () => json(200, { artifacts: [artifact()] }),
    [`GET /api/v1/artifacts/${artifactId}`]: () => json(200, artifact()),
    'GET /api/v1/catalog/deceptions/browser-bookmarks': () => json(200, catalogDeception()),
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
  '/artifacts',
  `/artifacts/${artifactId}`,
  '/catalog',
  '/catalog/browser-bookmarks',
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
