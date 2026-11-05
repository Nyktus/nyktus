// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises } from '@vue/test-utils';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { arrive, boot, submit } from './testing/boot';
import { catalogDeception, catalogSummary, failure, fakeServer, honeytoken, joined, json, scenario, scenarioId, sessionBody } from './testing/fakeServer';

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = '';
  history.replaceState(null, '', '/');
});

type Role = 'admin' | 'user' | 'viewer';

const detail = `/api/v1/scenarios/${scenarioId}`;
const webToken = honeytoken({ id: 'c0ffee00-aaaa-4222-8333-944444444444', name: 'Portal link', type: 'web_url', scenario_id: scenarioId });

function server(role: Role = 'admin', extra: Record<string, () => Response> = {}) {
  return fakeServer({
    'GET /api/v1/session': () => json(200, sessionBody(role)),
    [`GET ${detail}`]: () => json(200, scenario({ deceptions: [joined('ssh-jump-host')] })),
    'GET /api/v1/honeytokens': () => json(200, { honeytokens: [webToken] }),
    'GET /api/v1/honeypots': () => json(200, { honeypots: [] }),
    'GET /api/v1/catalog/deceptions': () => json(200, { deceptions: [catalogSummary(), catalogSummary({ id: 'ssh-jump-host', title: 'SSH jump host' })] }),
    'GET /api/v1/catalog/deceptions/browser-bookmarks': () => json(200, catalogDeception()),
    'GET /api/v1/catalog/deceptions/ssh-jump-host': () => json(200, catalogDeception({ id: 'ssh-jump-host', title: 'SSH jump host', guide: '## One' })),
    ...extra,
  });
}

describe('the deceptions of a scenario', () => {
  test('are the ones that joined it, each named by its title and with its guide from the catalog', async () => {
    const s = server('admin', {
      [`GET ${detail}`]: () => json(200, scenario({ deceptions: [joined('ssh-jump-host'), joined('browser-bookmarks')] })),
      'GET /api/v1/catalog/deceptions/browser-bookmarks': () => json(200, catalogDeception({ guide: '## Two' })),
    });
    const { wrapper } = await boot(s, `/scenarios/${scenarioId}`);
    const stories = wrapper.findAll('article.story');
    expect(stories.map((a) => a.get('h3 a').text())).toEqual(['SSH jump host', 'Browser bookmarks']);
    expect(stories[0]?.get('h3 a').attributes('href')).toBe('/catalog/ssh-jump-host');
    expect(stories[0]?.text()).toContain('Added');
    expect(stories.map((a) => a.get('.markdown h4').text())).toEqual(['One', 'Two']);
  });

  test('keep the guide behind a fold, whether there is one or several', async () => {
    for (const joinedIds of [['ssh-jump-host'], ['ssh-jump-host', 'browser-bookmarks']]) {
      const s = server('admin', { [`GET ${detail}`]: () => json(200, scenario({ deceptions: joinedIds.map((id) => joined(id)) })) });
      const { wrapper } = await boot(s, `/scenarios/${scenarioId}`);
      for (const details of wrapper.findAll('article.story details')) {
        expect(details.attributes('open')).toBeUndefined();
        expect(details.get('summary').text()).toBe('Guide');
      }
      document.body.innerHTML = '';
    }
  });

  test('explain what to do next when there are none, to whoever may add one', async () => {
    const empty = { [`GET ${detail}`]: () => json(200, scenario()) };
    const admin = await boot(server('admin', empty), `/scenarios/${scenarioId}`);
    expect(admin.wrapper.text()).toContain('No deception has been assigned to this scenario yet.');
    expect(admin.wrapper.get(`a[href="/scenarios/${scenarioId}/deceptions/new"]`).text()).toBe('Add deception');
    document.body.innerHTML = '';
    const viewer = await boot(server('viewer', empty), `/scenarios/${scenarioId}`);
    expect(viewer.wrapper.text()).toContain('No deception has been assigned to this scenario.');
    expect(viewer.wrapper.find(`a[href="/scenarios/${scenarioId}/deceptions/new"]`).exists()).toBe(false);
  });

  test('do not ask the catalog for titles before the scenario has been read', async () => {
    const s = server('admin', { [`GET ${detail}`]: () => new Promise<Response>(() => undefined) as never });
    const { i18n } = await boot(s, `/scenarios/${scenarioId}`);
    i18n.setLocale('de');
    await flushPromises();
    expect(s.requests.some((r) => r.url.startsWith('/api/v1/catalog/deceptions'))).toBe(false);
  });

  test('show a title of the catalog as text', async () => {
    const s = server('admin', { 'GET /api/v1/catalog/deceptions': () => json(200, { deceptions: [catalogSummary({ id: 'ssh-jump-host', title: '<b>Jump</b>' })] }) });
    const { wrapper } = await boot(s, `/scenarios/${scenarioId}`);
    expect(wrapper.get('article.story h3').text()).toBe('<b>Jump</b>');
    expect(wrapper.find('article.story h3 b').exists()).toBe(false);
  });

  test('have no files of their own', async () => {
    const s = server();
    const { wrapper } = await boot(s, `/scenarios/${scenarioId}`);
    expect(s.requests.some((r) => r.url.startsWith('/api/v1/artifacts'))).toBe(false);
    expect(wrapper.find('a[href$="/artifacts/new"]').exists()).toBe(false);
  });

  test('are removed after a question that says that the resources stay', async () => {
    const removed = scenario();
    const s = server('admin', { [`DELETE ${detail}/deceptions/ssh-jump-host`]: () => json(200, removed) });
    const { wrapper } = await boot(s, `/scenarios/${scenarioId}`);
    expect(wrapper.find('dialog[open]').exists()).toBe(false);
    await wrapper.get('article.story .head button').trigger('click');
    await flushPromises();
    const question = wrapper.get('dialog[open]');
    expect(question.text()).toContain('Remove this deception?');
    expect(question.text()).toContain('Its honeytokens and honeypots stay in the scenario.');
    expect(s.requests.filter((r) => r.method === 'DELETE')).toHaveLength(0);
    await question.get('.button-primary').trigger('click');
    await flushPromises();
    expect(s.requests.filter((r) => r.method === 'DELETE').map((r) => r.url)).toEqual([`${detail}/deceptions/ssh-jump-host`]);
    expect(wrapper.find('article.story').exists()).toBe(false);
    expect(wrapper.find('dialog[open]').exists()).toBe(false);
  });

  test('stay when the question is answered with no', async () => {
    const s = server('admin', { [`DELETE ${detail}/deceptions/ssh-jump-host`]: () => json(200, scenario()) });
    const { wrapper } = await boot(s, `/scenarios/${scenarioId}`);
    await wrapper.get('article.story .head button').trigger('click');
    await flushPromises();
    await wrapper.get('dialog[open] .button-ghost').trigger('click');
    await flushPromises();
    expect(s.requests.filter((r) => r.method === 'DELETE')).toHaveLength(0);
    expect(wrapper.find('article.story').exists()).toBe(true);
    expect(wrapper.find('dialog[open]').exists()).toBe(false);
  });

  test('say why a removal failed, and keep the deception', async () => {
    const s = server('admin', { [`DELETE ${detail}/deceptions/ssh-jump-host`]: () => failure(503, 'unavailable') });
    const { wrapper } = await boot(s, `/scenarios/${scenarioId}`);
    await wrapper.get('article.story .head button').trigger('click');
    await flushPromises();
    await wrapper.get('dialog[open] .button-primary').trigger('click');
    await flushPromises();
    expect(wrapper.get('[role=alert]').text()).toBe('The server is busy. Try again in a moment.');
    expect(wrapper.find('article.story').exists()).toBe(true);
    expect(wrapper.find('dialog[open]').exists()).toBe(false);
  });
});

describe('adding a deception', () => {
  const path = `/scenarios/${scenarioId}/deceptions/new`;
  const add = `POST ${detail}/deceptions`;
  const added = () => json(201, { scenario: scenario(), honeytokens: [], honeypots: [] });

  async function choose(wrapper: Awaited<ReturnType<typeof boot>>['wrapper'], id = 'browser-bookmarks') {
    await wrapper.get('#deception').setValue(id);
    await flushPromises();
  }

  test('offers the deceptions that are not part of the scenario, and names the others as part of it', async () => {
    const { wrapper } = await boot(server(), path);
    const options = wrapper.findAll('#deception option').map((o) => [o.text(), (o.element as HTMLOptionElement).disabled]);
    expect(options).toEqual([
      ['Choose a deception', false],
      ['Browser bookmarks', false],
      ['SSH jump host (already part of this scenario)', true],
    ]);
  });

  test('says that nothing is left to add', async () => {
    const all = server('admin', { 'GET /api/v1/catalog/deceptions': () => json(200, { deceptions: [catalogSummary({ id: 'ssh-jump-host' })] }) });
    const { wrapper } = await boot(all, path);
    expect(wrapper.text()).toContain('No deceptions left to add.');
    expect(wrapper.find('form').exists()).toBe(false);
  });

  test('asks for no value of a persona and offers no files', async () => {
    const { wrapper } = await boot(server(), path);
    await choose(wrapper);
    expect(wrapper.find('[id^=persona-]').exists()).toBe(false);
    expect(wrapper.find('fieldset.files').exists()).toBe(false);
  });

  test('sends the deception, the language of the console and no request for the resources unless asked', async () => {
    const s = server('admin', { [add]: added });
    const { wrapper, router, i18n } = await boot(s, path);
    i18n.setLocale('de');
    await flushPromises();
    await choose(wrapper);
    expect((wrapper.get('#create-resources').element as HTMLInputElement).checked).toBe(false);
    await submit(wrapper);
    expect(s.requests.find((r) => r.method === 'POST')?.body).toEqual({ deception_id: 'browser-bookmarks', language: 'de', create_resources: false });
    await arrive(router, 'scenario');
  });

  test('asks for the resources when the box is ticked, and only offers it to whoever may write both', async () => {
    const s = server('user', { [add]: added });
    const { wrapper } = await boot(s, path);
    await choose(wrapper);
    await wrapper.get('#create-resources').setValue(true);
    await submit(wrapper);
    expect(s.requests.find((r) => r.method === 'POST')?.body).toMatchObject({ create_resources: true });
  });

  test('says why the server refused it, and keeps the form', async () => {
    for (const [status, code, text] of [
      [409, 'deception_already_added', 'already assigned to the scenario'],
      [422, 'dns_not_configured', 'NYKTUS_DNS_ZONES'],
    ] as const) {
      const { wrapper } = await boot(server('admin', { [add]: () => failure(status, code) }), path);
      await choose(wrapper);
      await submit(wrapper);
      expect(wrapper.get('[role=alert]').text(), code).toContain(text);
      expect(wrapper.find('form').exists(), code).toBe(true);
      document.body.innerHTML = '';
    }
  });

  test('shows nothing to add while the answer for another choice is on its way', async () => {
    const s = server('admin', {
      'GET /api/v1/catalog/deceptions': () => json(200, { deceptions: [catalogSummary(), catalogSummary({ id: 'second', title: 'Second' })] }),
      'GET /api/v1/catalog/deceptions/second': () => new Promise<Response>(() => undefined) as never,
      [add]: added,
    });
    const { wrapper } = await boot(s, path);
    await choose(wrapper, 'browser-bookmarks');
    expect(wrapper.find('#create-resources').exists()).toBe(true);
    await choose(wrapper, 'second');
    expect(wrapper.find('button[type=submit]').exists()).toBe(false);
    expect(s.requests.filter((r) => r.method === 'POST')).toHaveLength(0);
  });

  test('says when the scenario does not exist', async () => {
    const { wrapper } = await boot(server('admin', { [`GET ${detail}`]: () => failure(404, 'not_found') }), path);
    expect(wrapper.get('[role=status]').text()).toBe('Nothing found here.');
  });

  test('shows what was chosen last when the answers come in the other order', async () => {
    const answers: Record<string, (response: Response) => void> = {};
    const wait = (id: string) => () => new Promise<Response>((resolve) => (answers[id] = resolve)) as never;
    const s = server('admin', {
      'GET /api/v1/catalog/deceptions': () => json(200, { deceptions: [catalogSummary(), catalogSummary({ id: 'second', title: 'Second' })] }),
      'GET /api/v1/catalog/deceptions/browser-bookmarks': wait('first'),
      'GET /api/v1/catalog/deceptions/second': wait('second'),
    });
    const { wrapper } = await boot(s, path);
    await choose(wrapper, 'browser-bookmarks');
    await choose(wrapper, 'second');
    answers.second?.(json(200, catalogDeception({ id: 'second', summary: 'Chosen last.' })));
    await flushPromises();
    answers.first?.(json(200, catalogDeception({ summary: 'Chosen first.' })));
    await flushPromises();
    expect(wrapper.text()).toContain('Chosen last.');
    expect(wrapper.text()).not.toContain('Chosen first.');
  });
});
