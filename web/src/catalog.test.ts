// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises } from '@vue/test-utils';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { arrive, boot, submit, type } from './testing/boot';
import { catalogDeception, catalogSummary, failure, fakeServer, joined, json, scenario, scenarioId, sessionBody } from './testing/fakeServer';

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = '';
  history.replaceState(null, '', '/');
});

type Role = 'admin' | 'user' | 'viewer';

const one = '/api/v1/catalog/deceptions/browser-bookmarks';

function server(role: Role = 'admin', extra: Record<string, () => Response> = {}) {
  return fakeServer({
    'GET /api/v1/session': () => json(200, sessionBody(role)),
    'GET /api/v1/catalog/deceptions': () => json(200, { deceptions: [catalogSummary(), catalogSummary({ id: 'ssh-jump-host', category: 'network', title: 'SSH jump host' })] }),
    [`GET ${one}`]: () => json(200, catalogDeception()),
    'GET /api/v1/scenarios': () => json(200, { scenarios: [] }),
    ...extra,
  });
}

describe('the catalog', () => {
  test('lists the deceptions in the language of the console', async () => {
    const s = server();
    const { wrapper } = await boot(s, '/catalog');
    expect(wrapper.findAll('.card h2').map((h) => h.text())).toEqual(['Browser bookmarks', 'SSH jump host']);
    expect(s.requests.at(-1)?.url).toBe('/api/v1/catalog/deceptions?lang=en');
    expect(wrapper.get('.card a').attributes('href')).toBe('/catalog/browser-bookmarks');
  });

  test('asks again when the language changes', async () => {
    const s = server();
    const { i18n } = await boot(s, '/catalog');
    i18n.setLocale('de');
    await flushPromises();
    expect(s.requests.at(-1)?.url).toBe('/api/v1/catalog/deceptions?lang=de');
  });

  test('narrows the list by category', async () => {
    const { wrapper } = await boot(server(), '/catalog');
    await wrapper.get('#filter-category').setValue('network');
    expect(wrapper.findAll('.card h2').map((h) => h.text())).toEqual(['SSH jump host']);
    await wrapper.get('#filter-category').setValue('identity');
    expect(wrapper.text()).toContain('No deception matches the filter.');
  });

  test('says when it could not be loaded', async () => {
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/catalog/deceptions': () => failure(503, 'unavailable') }), '/catalog');
    expect(wrapper.get('[role=alert]').text()).toContain('The catalog could not be loaded.');
  });

  test('is in the navigation of every role', async () => {
    const { wrapper } = await boot(server('viewer'), '/catalog');
    expect(wrapper.get('nav').text()).toContain('Catalog');
  });
});

describe('a deception', () => {
  const path = '/catalog/browser-bookmarks';
  const apply = 'POST /api/v1/catalog/deceptions/browser-bookmarks/apply';

  test('shows what applying it creates', async () => {
    const { wrapper } = await boot(server(), path);
    expect(wrapper.get('h1').text()).toBe('Browser bookmarks');
    expect(wrapper.text()).toContain('Portal link');
    expect(wrapper.text()).toContain('Web URL');
    expect(wrapper.text()).toContain('bookmarks.html');
    expect(wrapper.text()).toContain('HTML');
    expect(wrapper.text()).toContain('1 generated when it is applied');
    expect(wrapper.text()).toContain('T1217');
    expect(wrapper.text()).toContain('EAC0005');
  });

  test('says when it consists of its guide', async () => {
    const guide = server('admin', { [`GET ${one}`]: () => json(200, catalogDeception({ honeytokens: [], artifacts: [], secrets: [], persona: [] })) });
    const { wrapper } = await boot(guide, path);
    expect(wrapper.text()).toContain('This deception consists of its guide.');
    expect(wrapper.find('fieldset').exists()).toBe(false);
  });

  test('says when it does not exist', async () => {
    const { wrapper } = await boot(server('admin', { [`GET ${one}`]: () => failure(404, 'not_found') }), path);
    expect(wrapper.get('[role=status]').text()).toBe('This does not exist.');
  });

  test('is only read by a viewer', async () => {
    const { wrapper } = await boot(server('viewer'), path);
    expect(wrapper.get('h1').text()).toBe('Browser bookmarks');
    expect(wrapper.find('form').exists()).toBe(false);
  });

  test('says so to a viewer when it could not be read again, and keeps showing what it has', async () => {
    const s = server('viewer');
    const { wrapper, i18n } = await boot(s, path);
    s.on(`GET ${one}`, () => failure(503, 'unavailable'));
    i18n.setLocale('de');
    await flushPromises();
    expect(wrapper.get('[role=alert]').text()).toBe('Der Server ist ausgelastet. Versuchen Sie es gleich noch einmal.');
    expect(wrapper.get('h1').text()).toBe('Browser bookmarks');
  });

  test('shows what was asked for last when the answers come in the other order', async () => {
    const answers: ((response: Response) => void)[] = [];
    const s = server('viewer');
    const { wrapper, i18n } = await boot(s, path);
    s.on(`GET ${one}`, () => new Promise<Response>((resolve) => answers.push(resolve)) as never);
    i18n.setLocale('de');
    await flushPromises();
    i18n.setLocale('en');
    await flushPromises();
    expect(answers).toHaveLength(2);
    answers[1]?.(json(200, catalogDeception({ title: 'Browser bookmarks (en)' })));
    await flushPromises();
    answers[0]?.(json(200, catalogDeception({ title: 'Lesezeichen (de)' })));
    await flushPromises();
    expect(wrapper.get('h1').text()).toBe('Browser bookmarks (en)');
  });

  describe('applied', () => {
    const created = () => json(201, { scenario: scenario({ deceptions: [joined('browser-bookmarks')] }), honeytokens: [], artifacts: [] });

    async function fill(wrapper: Awaited<ReturnType<typeof boot>>['wrapper'], company = 'Acme Corp', host = 'portal.acme.example') {
      await type(wrapper, '#persona-company', company);
      await type(wrapper, '#persona-host', host);
    }

    test('suggests the name of the deception, and shows an example for each value without filling it in', async () => {
      const { wrapper } = await boot(server(), path);
      expect((wrapper.get('#name').element as HTMLInputElement).value).toBe('Browser bookmarks');
      expect((wrapper.get('#persona-company').element as HTMLInputElement).value).toBe('');
      expect(wrapper.get('#persona-company').attributes('placeholder')).toBe('Acme Corp');
      expect(wrapper.text()).toContain('For example: portal.acme.example');
    });

    test('asks for a name that is more than spaces, before it asks the server', async () => {
      const s = server('admin', { [apply]: created });
      const { wrapper } = await boot(s, path);
      await type(wrapper, '#name', '   ');
      await fill(wrapper);
      await submit(wrapper);
      expect(wrapper.get('#name-problem').text()).toBe('Enter a name.');
      expect(s.requests.filter((r) => r.method === 'POST')).toHaveLength(0);
    });

    test('accepts values with spaces around them, which it sends without', async () => {
      const s = server('admin', { [apply]: created, [`GET /api/v1/scenarios/${scenarioId}`]: () => json(200, scenario()) });
      const { wrapper } = await boot(s, path);
      await fill(wrapper, ' Acme Corp ', ' portal.acme.example ');
      await submit(wrapper);
      expect(s.requests.find((r) => r.method === 'POST')?.body).toMatchObject({ persona: { company: 'Acme Corp', host: 'portal.acme.example' } });
    });

    test('sends the name, the language and every value, and shows the new scenario', async () => {
      const s = server('admin', { [apply]: created, [`GET /api/v1/scenarios/${scenarioId}`]: () => json(200, scenario({ deceptions: [joined('browser-bookmarks')] })), [`GET /api/v1/scenarios/${scenarioId}/guide`]: () => json(200, { guides: [{ deception_id: 'browser-bookmarks', language: 'en', content: '# Guide' }] }) });
      const { wrapper, router } = await boot(s, path);
      await type(wrapper, '#name', '  Bookmarks of IT  ');
      await type(wrapper, '#notes', 'On the file share.');
      await wrapper.get('#guide-language').setValue('de');
      await fill(wrapper, '  Acme Corp ');
      await submit(wrapper);
      expect(s.requests.find((r) => r.method === 'POST')?.body).toEqual({
        name: 'Bookmarks of IT',
        notes: 'On the file share.',
        language: 'de',
        persona: { company: 'Acme Corp', host: 'portal.acme.example' },
      });
      await arrive(router, 'scenario');
    });

    test('does not send a value that the kind does not allow, and says which', async () => {
      const s = server('admin', { [apply]: created });
      const { wrapper } = await boot(s, path);
      await fill(wrapper, '', 'Portal_Host');
      await submit(wrapper);
      const alerts = wrapper.findAll('.problem').map((a) => a.text());
      expect(alerts).toEqual(['Enter a value for Company.', 'Portal host must be a host name of lowercase letters, digits, hyphens and dots.']);
      expect(s.requests.filter((r) => r.method === 'POST')).toHaveLength(0);
    });

    test('explains that DNS honeytokens need a zone, and that a value may reveal the decoy', async () => {
      for (const [code, text] of [
        ['dns_not_configured', 'NYKTUS_DNS_ZONES'],
        ['artifact_reveals_decoy', 'reveal what it is'],
      ] as const) {
        const { wrapper } = await boot(server('admin', { [apply]: () => failure(422, code) }), path);
        await fill(wrapper);
        await submit(wrapper);
        expect(wrapper.get('[role=alert]').text(), code).toContain(text);
        expect(wrapper.find('form').exists()).toBe(true);
        document.body.innerHTML = '';
      }
    });

    test('keeps what was typed for a failure', async () => {
      const { wrapper } = await boot(server('admin', { [apply]: () => failure(503, 'unavailable') }), path);
      await fill(wrapper);
      await submit(wrapper);
      expect((wrapper.get('#persona-company').element as HTMLInputElement).value).toBe('Acme Corp');
    });
  });
});

describe('the guide of a scenario', () => {
  const detail = `/api/v1/scenarios/${scenarioId}`;
  const fromCatalog = scenario({ deceptions: [joined('browser-bookmarks')], persona: { company: 'Acme Corp' } });

  function sc(extra: Record<string, () => Response> = {}) {
    return server('admin', {
      [`GET ${detail}`]: () => json(200, fromCatalog),
      'GET /api/v1/honeytokens': () => json(200, { honeytokens: [] }),
      'GET /api/v1/artifacts': () => json(200, { artifacts: [] }),
      'GET /api/v1/honeypots': () => json(200, { honeypots: [] }),
      ...extra,
    });
  }

  test('is shown as text with its structure', async () => {
    const s = sc({ [`GET ${detail}/guide`]: () => json(200, { guides: [{ deception_id: 'browser-bookmarks', language: 'en', content: '# Bookmarks\n\n## Place it\n\n1. Do this.\n2. Do that.\n\n```\nopen file\n```' }] }) });
    const { wrapper } = await boot(s, `/scenarios/${scenarioId}`);
    const guide = wrapper.get('.markdown');
    expect(guide.get('h2').text()).toBe('Bookmarks');
    expect(guide.get('h3').text()).toBe('Place it');
    expect(guide.findAll('ol li')).toHaveLength(2);
    expect(guide.get('pre').text()).toBe('open file');
    expect(wrapper.text()).toContain('Language of the guide: en');
  });

  // The guide names values that a person typed, and the console shows them as text.
  test('shows markup in it as text', async () => {
    const s = sc({ [`GET ${detail}/guide`]: () => json(200, { guides: [{ deception_id: 'browser-bookmarks', language: 'en', content: 'Company: <img src=x onerror=alert(1)> [x](javascript:alert(2))' }] }) });
    const { wrapper } = await boot(s, `/scenarios/${scenarioId}`);
    expect(wrapper.find('.markdown img').exists()).toBe(false);
    expect(wrapper.find('.markdown a').exists()).toBe(false);
    expect(wrapper.get('.markdown').text()).toContain('<img src=x onerror=alert(1)>');
  });

  test('says when it could not be loaded', async () => {
    const { wrapper } = await boot(sc({ [`GET ${detail}/guide`]: () => failure(503, 'unavailable') }), `/scenarios/${scenarioId}`);
    expect(wrapper.text()).toContain('The guide could not be loaded.');
  });

  test('is not asked for when the scenario was put together by hand', async () => {
    const s = sc({ [`GET ${detail}`]: () => json(200, scenario()) });
    const { wrapper } = await boot(s, `/scenarios/${scenarioId}`);
    expect(s.requests.some((r) => r.url.endsWith('/guide'))).toBe(false);
    expect(wrapper.find('.markdown').exists()).toBe(false);
  });
});
