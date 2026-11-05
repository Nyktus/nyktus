// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises } from '@vue/test-utils';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { arrive, boot, submit, type } from './testing/boot';
import { catalogDeception, catalogSummary, failure, fakeServer, joined, json, scenario, scenarioId, sessionBody } from './testing/fakeServer';

// The console saves a file with a link that it makes, and never opens it.
const saved: { download: string; href: string }[] = [];

beforeEach(() => {
  saved.length = 0;
  vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: vi.fn(() => 'blob:console/1'), revokeObjectURL: vi.fn() }));
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
    saved.push({ download: this.download, href: this.href });
  });
});

afterEach(() => {
  vi.restoreAllMocks();
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

  test('has no tab for files of its own', async () => {
    const s = server();
    const { wrapper } = await boot(s, '/catalog');
    expect(wrapper.find('nav[aria-label="Parts of the catalog"]').exists()).toBe(false);
    expect(wrapper.get('nav').text()).not.toContain('Artifacts');
    expect(s.requests.some((r) => r.url.includes('artifacts'))).toBe(false);
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
    expect(wrapper.text()).toContain('No deceptions found.');
  });

  test('offers the cloud category in the filter, in both languages', async () => {
    const { wrapper, i18n } = await boot(server(), '/catalog');
    const option = () => wrapper.get('#filter-category option[value=cloud]').text();
    expect(option()).toBe('Cloud');
    i18n.setLocale('de');
    await flushPromises();
    expect(option()).toBe('Cloud');
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
  const file = `GET ${one}/files/bookmarks.html`;

  test('shows its guide as text, the slots it asks for and its files', async () => {
    const { wrapper } = await boot(server(), path);
    expect(wrapper.get('h1').text()).toBe('Browser bookmarks');
    expect(wrapper.get('.markdown').text()).toContain('with Honeytoken-URL as the link');
    expect(wrapper.text()).toContain('Portal link');
    expect(wrapper.text()).toContain('Web URL');
    expect(wrapper.text()).toContain('bookmarks.html');
    expect(wrapper.text()).toContain('HTML');
    expect(wrapper.text()).toContain('2 KiB');
    expect(wrapper.text()).toContain('T1217');
    expect(wrapper.text()).toContain('EAC0005');
    expect(wrapper.text()).toContain('Replace Honeytoken-Domain or Honeytoken-URL');
    expect(wrapper.text()).toContain('Lures (EAC0005)');
  });

  test('shows the honeypots that it asks for by their service', async () => {
    const withPots = server('viewer', { [`GET ${one}`]: () => json(200, catalogDeception({ honeypots: [{ label: 'Database', service: 'postgres' }] })) });
    const { wrapper } = await boot(withPots, path);
    expect(wrapper.text()).toContain('Honeypots');
    expect(wrapper.text()).toContain('Database');
    expect(wrapper.text()).toContain('PostgreSQL');
  });

  test('shows the guide with its markup as text', async () => {
    const guide = 'Company: <img src=x onerror=alert(1)> [x](javascript:alert(2))';
    const { wrapper } = await boot(server('viewer', { [`GET ${one}`]: () => json(200, catalogDeception({ guide })) }), path);
    expect(wrapper.find('.markdown img').exists()).toBe(false);
    expect(wrapper.find('.markdown a').exists()).toBe(false);
    expect(wrapper.get('.markdown').text()).toContain('<img src=x onerror=alert(1)>');
  });

  test('says so when it asks for nothing to create and offers no file', async () => {
    const bare = server('admin', { [`GET ${one}`]: () => json(200, catalogDeception({ honeytokens: [], honeypots: [], files: [] })) });
    const { wrapper } = await boot(bare, path);
    expect(wrapper.text()).toContain('This deception asks for no honeytoken and no honeypot.');
    expect(wrapper.text()).not.toContain('Example files');
    expect(wrapper.find('#create-resources').exists()).toBe(false);
  });

  test('says when it does not exist', async () => {
    const { wrapper } = await boot(server('admin', { [`GET ${one}`]: () => failure(404, 'not_found') }), path);
    expect(wrapper.get('[role=status]').text()).toBe('Nothing found here.');
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

  describe('downloaded file', () => {
    const content = () =>
      new Response('<html><script>alert(1)</script></html>', { status: 200, headers: { 'Content-Type': 'text/html', 'Content-Disposition': 'attachment; filename="bookmarks.html"' } });

    test('is saved under its name and never opened or shown', async () => {
      const s = server('viewer', { [file]: content });
      const { wrapper } = await boot(s, path);
      await wrapper.get('table button').trigger('click');
      await flushPromises();
      expect(saved).toEqual([{ download: 'bookmarks.html', href: 'blob:console/1' }]);
      expect(vi.mocked(URL.createObjectURL).mock.calls[0]?.[0]).toBeInstanceOf(Blob);
      expect(wrapper.text()).not.toContain('alert(1)');
      expect(document.body.querySelectorAll('a[download]')).toHaveLength(0);
    });

    test('asks for the name that it has, also when it holds a space', async () => {
      const spaced = server('viewer', {
        [`GET ${one}`]: () => json(200, catalogDeception({ files: [{ name: 'Read me.txt', format: 'text', size: 12 }] })),
        [`GET ${one}/files/Read%20me.txt`]: content,
      });
      const { wrapper } = await boot(spaced, path);
      await wrapper.get('table button').trigger('click');
      await flushPromises();
      expect(saved.map((f) => f.download)).toEqual(['Read me.txt']);
    });

    test('says when it could not be downloaded', async () => {
      const { wrapper } = await boot(server('viewer', { [file]: () => failure(503, 'unavailable') }), path);
      await wrapper.get('table button').trigger('click');
      await flushPromises();
      expect(wrapper.get('[role=alert]').text()).toContain('The file could not be downloaded.');
      expect(saved).toEqual([]);
    });
  });

  describe('applied', () => {
    const created = () => json(201, { scenario: scenario({ deceptions: [joined('browser-bookmarks')] }), honeytokens: [], honeypots: [] });

    test('suggests the name of the deception', async () => {
      const { wrapper } = await boot(server(), path);
      expect((wrapper.get('#name').element as HTMLInputElement).value).toBe('Browser bookmarks');
    });

    test('asks for the name and the notes of the scenario and for nothing of the files', async () => {
      const { wrapper } = await boot(server(), path);
      expect(wrapper.find('[id^=persona-]').exists()).toBe(false);
      expect(wrapper.find('fieldset.files').exists()).toBe(false);
    });

    test('creates no resources unless the box is ticked, which is off at first', async () => {
      const s = server('admin', { [apply]: created, [`GET /api/v1/scenarios/${scenarioId}`]: () => json(200, scenario()) });
      const { wrapper } = await boot(s, path);
      expect((wrapper.get('#create-resources').element as HTMLInputElement).checked).toBe(false);
      await submit(wrapper);
      expect(s.requests.find((r) => r.method === 'POST')?.body).toMatchObject({ create_resources: false });
    });

    test('asks for the resources when the box is ticked', async () => {
      const s = server('user', { [apply]: created, [`GET /api/v1/scenarios/${scenarioId}`]: () => json(200, scenario()) });
      const { wrapper } = await boot(s, path);
      await wrapper.get('#create-resources').setValue(true);
      await submit(wrapper);
      expect(s.requests.find((r) => r.method === 'POST')?.body).toMatchObject({ create_resources: true });
    });

    test('offers the box to whoever may write both honeytokens and honeypots, which a role has together', async () => {
      for (const role of ['admin', 'user'] as const) {
        const { wrapper } = await boot(server(role), path);
        expect(wrapper.find('#create-resources').exists(), role).toBe(true);
        document.body.innerHTML = '';
      }
    });

    test('asks for a name that is more than spaces, before it asks the server', async () => {
      const s = server('admin', { [apply]: created });
      const { wrapper } = await boot(s, path);
      await type(wrapper, '#name', '   ');
      await submit(wrapper);
      expect(wrapper.get('#name-problem').text()).toBe('Enter a name.');
      expect(s.requests.filter((r) => r.method === 'POST')).toHaveLength(0);
    });

    test('sends the name, the notes and the language of the console, and shows the new scenario', async () => {
      const s = server('admin', {
        [apply]: created,
        [`GET /api/v1/scenarios/${scenarioId}`]: () => json(200, scenario({ deceptions: [joined('browser-bookmarks')] })),
        [`GET ${one}`]: () => json(200, catalogDeception()),
      });
      const { wrapper, router, i18n } = await boot(s, path);
      i18n.setLocale('de');
      await flushPromises();
      await type(wrapper, '#name', '  Bookmarks of IT  ');
      await type(wrapper, '#notes', 'On the file share.');
      await submit(wrapper);
      expect(s.requests.find((r) => r.method === 'POST')?.body).toEqual({
        name: 'Bookmarks of IT',
        notes: 'On the file share.',
        language: 'de',
        create_resources: false,
      });
      await arrive(router, 'scenario');
    });

    test('explains that DNS honeytokens need a zone', async () => {
      const { wrapper } = await boot(server('admin', { [apply]: () => failure(422, 'dns_not_configured') }), path);
      await wrapper.get('#create-resources').setValue(true);
      await submit(wrapper);
      expect(wrapper.get('[role=alert]').text()).toContain('NYKTUS_DNS_ZONES');
      expect(wrapper.find('form').exists()).toBe(true);
    });

    test('keeps what was typed for a failure', async () => {
      const { wrapper } = await boot(server('admin', { [apply]: () => failure(503, 'unavailable') }), path);
      await type(wrapper, '#notes', 'On the file share.');
      await submit(wrapper);
      expect((wrapper.get('#notes').element as HTMLTextAreaElement).value).toBe('On the file share.');
    });
  });
});

describe('the deceptions of a scenario', () => {
  const detail = `/api/v1/scenarios/${scenarioId}`;
  const held = scenario({ deceptions: [joined('browser-bookmarks')] });

  function sc(extra: Record<string, () => Response> = {}) {
    return server('admin', {
      [`GET ${detail}`]: () => json(200, held),
      'GET /api/v1/honeytokens': () => json(200, { honeytokens: [] }),
      'GET /api/v1/honeypots': () => json(200, { honeypots: [] }),
      ...extra,
    });
  }

  /** Confirms the question that appears when a deception is to be removed. */
  async function confirmRemoval(wrapper: Awaited<ReturnType<typeof boot>>['wrapper']): Promise<void> {
    await wrapper.get('.story .head button').trigger('click');
    await flushPromises();
    await wrapper.get('dialog[open] .button-primary').trigger('click');
    await flushPromises();
  }

  test('show the guide from the catalog as text with its structure, behind a fold, in the language of the console', async () => {
    const s = sc({ [`GET ${one}`]: () => json(200, catalogDeception({ guide: '# Bookmarks\n\n## Place it\n\n1. Do this.\n2. Do that.\n\n```\nopen file\n```' })) });
    const { wrapper, i18n } = await boot(s, `/scenarios/${scenarioId}`);
    const guide = wrapper.get('.story details .markdown');
    // The guide stands under the title of its story, a level 3, so its first heading is a level 4.
    expect(guide.get('h4').text()).toBe('Bookmarks');
    expect(guide.get('h5').text()).toBe('Place it');
    expect(guide.findAll('ol li')).toHaveLength(2);
    expect(guide.get('pre').text()).toBe('open file');
    expect(wrapper.get('.story details summary').text()).toBe('Guide');
    expect(wrapper.get('.story details').attributes('open')).toBeUndefined();
    expect(wrapper.text()).toContain('Added');
    expect(wrapper.get('.story h3 a').text()).toBe('Browser bookmarks');
    expect(s.requests.some((r) => r.url === `${one}?lang=en`)).toBe(true);
    i18n.setLocale('de');
    await flushPromises();
    expect(s.requests.at(-1)?.url).toBe(`${one}?lang=de`);
    expect(s.requests.some((r) => r.url === '/api/v1/catalog/deceptions?lang=de')).toBe(true);
  });

  test('read the slots and the guide of every deception at once, and the list of titles once', async () => {
    const s = sc({
      [`GET ${detail}`]: () => json(200, scenario({ deceptions: [joined('browser-bookmarks'), joined('ssh-jump-host')] })),
      'GET /api/v1/catalog/deceptions/ssh-jump-host': () => json(200, catalogDeception({ id: 'ssh-jump-host', title: 'SSH jump host', guide: 'Second guide.' })),
    });
    const { wrapper } = await boot(s, `/scenarios/${scenarioId}`);
    expect(wrapper.findAll('.story h3').map((h) => h.text())).toEqual(['Browser bookmarks', 'SSH jump host']);
    expect(s.requests.filter((r) => r.url.startsWith('/api/v1/catalog/deceptions')).map((r) => r.url)).toEqual([
      '/api/v1/catalog/deceptions?lang=en',
      `${one}?lang=en`,
      '/api/v1/catalog/deceptions/ssh-jump-host?lang=en',
    ]);
    expect(wrapper.findAll('.story .markdown')).toHaveLength(2);
    expect(wrapper.findAll('.story')[1]?.text()).toContain('Second guide.');
  });

  test('do not call a deception gone before the list of the catalog has been read', async () => {
    const answers: ((response: Response) => void)[] = [];
    const s = sc({ 'GET /api/v1/catalog/deceptions': () => new Promise<Response>((resolve) => answers.push(resolve)) as never });
    const { wrapper } = await boot(s, `/scenarios/${scenarioId}`);
    expect(wrapper.text()).not.toContain('This deception is not in the catalog any more.');
    expect(wrapper.get('.story h3').text()).toBe('browser-bookmarks');
    answers[0]?.(json(200, { deceptions: [catalogSummary()] }));
    await flushPromises();
    expect(wrapper.get('.story h3').text()).toBe('Browser bookmarks');
  });

  test('drop what was read in the language before, until it is read in the new one', async () => {
    const s = sc();
    const { wrapper, i18n } = await boot(s, `/scenarios/${scenarioId}`);
    expect(wrapper.get('.markdown').text()).toContain('Place the file');
    s.on(`GET ${one}`, () => new Promise<Response>(() => undefined) as never);
    i18n.setLocale('de');
    await flushPromises();
    expect(wrapper.find('.markdown').exists()).toBe(false);
    expect(wrapper.find('.story table').exists()).toBe(false);
    expect(wrapper.get('.story').text()).toContain('Wird geladen');
  });

  test('read a guide again in the new language when the language changes while it is being read', async () => {
    const answers: Record<string, (response: Response) => void> = {};
    const s = sc({ [`GET ${one}`]: () => new Promise<Response>(() => undefined) as never });
    const { wrapper, i18n } = await boot(s, `/scenarios/${scenarioId}`);
    s.on(`GET ${one}`, (request) => new Promise<Response>((resolve) => (answers[request.url] = resolve)) as never);
    i18n.setLocale('de');
    await flushPromises();
    expect(Object.keys(answers)).toEqual([`${one}?lang=de`]);
    answers[`${one}?lang=de`]?.(json(200, catalogDeception({ guide: 'Anleitung.' })));
    await flushPromises();
    expect(wrapper.get('.markdown').text()).toContain('Anleitung.');
  });

  test('show the answer for the language that is set, when the answers come in the other order', async () => {
    const answers: Record<string, (response: Response) => void> = {};
    const s = sc();
    s.on(`GET ${one}`, (request) => new Promise<Response>((resolve) => (answers[request.url] = resolve)) as never);
    const { wrapper, i18n } = await boot(s, `/scenarios/${scenarioId}`);
    i18n.setLocale('de');
    await flushPromises();
    answers[`${one}?lang=de`]?.(json(200, catalogDeception({ guide: 'Deutsch.' })));
    await flushPromises();
    answers[`${one}?lang=en`]?.(json(200, catalogDeception({ guide: 'English.' })));
    await flushPromises();
    expect(wrapper.get('.markdown').text()).toBe('Deutsch.');
  });

  test('say that the catalog does not know a deception any more, without asking for it, and let it be removed', async () => {
    const s = sc({
      'GET /api/v1/catalog/deceptions': () => json(200, { deceptions: [catalogSummary({ id: 'ssh-jump-host' })] }),
      [`DELETE ${detail}/deceptions/browser-bookmarks`]: () => json(200, scenario()),
    });
    const { wrapper } = await boot(s, `/scenarios/${scenarioId}`);
    expect(wrapper.text()).toContain('This deception is not in the catalog any more.');
    expect(wrapper.find('.markdown').exists()).toBe(false);
    expect(wrapper.find('.story a').exists()).toBe(false);
    expect(wrapper.get('.story h3').text()).toBe('browser-bookmarks');
    expect(s.requests.some((r) => r.url.startsWith(one))).toBe(false);
    await confirmRemoval(wrapper);
    expect(s.requests.some((r) => r.method === 'DELETE' && r.url === `${detail}/deceptions/browser-bookmarks`)).toBe(true);
    expect(wrapper.find('.story').exists()).toBe(false);
  });

  test('say when a guide could not be loaded, and ask again on request', async () => {
    const s = sc({ [`GET ${one}`]: () => failure(503, 'unavailable') });
    const { wrapper } = await boot(s, `/scenarios/${scenarioId}`);
    expect(wrapper.get('.story [role=alert]').text()).toContain('The guide could not be loaded.');
    s.on(`GET ${one}`, () => json(200, catalogDeception()));
    await wrapper.get('.story [role=alert] button').trigger('click');
    await flushPromises();
    expect(wrapper.find('.markdown').exists()).toBe(true);
    expect(wrapper.text()).not.toContain('The guide could not be loaded.');
  });

  test('say when the titles could not be loaded, keep the identifiers, and ask again on request', async () => {
    const s = sc({ 'GET /api/v1/catalog/deceptions': () => failure(503, 'unavailable') });
    const { wrapper } = await boot(s, `/scenarios/${scenarioId}`);
    expect(wrapper.text()).toContain('The guide could not be loaded.');
    expect(wrapper.get('.story h3').text()).toBe('browser-bookmarks');
    s.on('GET /api/v1/catalog/deceptions', () => json(200, { deceptions: [catalogSummary()] }));
    await wrapper.get('.section [role=alert] button').trigger('click');
    await flushPromises();
    expect(wrapper.get('.story h3').text()).toBe('Browser bookmarks');
    expect(wrapper.find('.markdown').exists()).toBe(true);
  });

  test('are not asked for when the scenario was put together by hand', async () => {
    const s = sc({ [`GET ${detail}`]: () => json(200, scenario()) });
    const { wrapper } = await boot(s, `/scenarios/${scenarioId}`);
    expect(s.requests.some((r) => r.url.startsWith('/api/v1/catalog/deceptions'))).toBe(false);
    expect(wrapper.find('.markdown').exists()).toBe(false);
  });

  test('are removed only by someone who may write scenarios', async () => {
    const { wrapper } = await boot(sc({ 'GET /api/v1/session': () => json(200, sessionBody('viewer')) }), `/scenarios/${scenarioId}`);
    expect(wrapper.find('.story .head button').exists()).toBe(false);
  });
});
