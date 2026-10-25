// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises } from '@vue/test-utils';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { arrive, boot, submit, type } from './testing/boot';
import { artifact, artifactId, catalogArtifact, catalogArtifactSummary, catalogDeception, catalogSummary, failure, fakeServer, honeytoken, joined, json, scenario, scenarioId, sessionBody } from './testing/fakeServer';

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = '';
  history.replaceState(null, '', '/');
});

type Role = 'admin' | 'user' | 'viewer';

const detail = `/api/v1/scenarios/${scenarioId}`;
const webToken = honeytoken({ id: 'c0ffee00-aaaa-4222-8333-944444444444', name: 'Portal link', type: 'web_url', scenario_id: scenarioId });
const dnsToken = honeytoken({
  id: 'c0ffee00-bbbb-4222-8333-944444444444',
  name: 'Portal name',
  type: 'dns',
  trigger_url: null,
  trigger_names: ['abc.t.example.net'],
  scenario_id: scenarioId,
});

function server(role: Role = 'admin', extra: Record<string, () => Response> = {}) {
  return fakeServer({
    'GET /api/v1/session': () => json(200, sessionBody(role)),
    [`GET ${detail}`]: () => json(200, scenario({ deceptions: [joined('ssh-jump-host')], persona: { company: 'Acme Corp' } })),
    [`GET ${detail}/guide`]: () => json(200, { guides: [{ deception_id: 'ssh-jump-host', language: 'en', content: '# One' }] }),
    'GET /api/v1/honeytokens': () => json(200, { honeytokens: [webToken, dnsToken] }),
    'GET /api/v1/artifacts': () => json(200, { artifacts: [] }),
    'GET /api/v1/honeypots': () => json(200, { honeypots: [] }),
    'GET /api/v1/catalog/deceptions': () => json(200, { deceptions: [catalogSummary(), catalogSummary({ id: 'ssh-jump-host', title: 'SSH jump host' })] }),
    'GET /api/v1/catalog/deceptions/browser-bookmarks': () => json(200, catalogDeception()),
    'GET /api/v1/catalog/artifacts': () => json(200, { artifacts: [catalogArtifactSummary(), catalogArtifactSummary({ id: 'notes', title: 'Notes file' })] }),
    'GET /api/v1/catalog/artifacts/bookmarks': () => json(200, catalogArtifact()),
    ...extra,
  });
}

describe('the stories of a scenario', () => {
  test('are the deceptions that joined it, each with its own guide', async () => {
    const s = server('admin', {
      [`GET ${detail}`]: () => json(200, scenario({ deceptions: [joined('ssh-jump-host'), joined('browser-bookmarks', 'de')] })),
      [`GET ${detail}/guide`]: () => json(200, { guides: [
        { deception_id: 'ssh-jump-host', language: 'en', content: '# One' },
        { deception_id: 'browser-bookmarks', language: 'de', content: '# Two' },
      ] }),
    });
    const { wrapper } = await boot(s, `/scenarios/${scenarioId}`);
    const stories = wrapper.findAll('article.story');
    expect(stories.map((a) => a.get('h3 a').text())).toEqual(['ssh-jump-host', 'browser-bookmarks']);
    expect(stories[0]?.get('h3 a').attributes('href')).toBe('/catalog/ssh-jump-host');
    expect(stories[0]?.text()).toContain('Language: en.');
    expect(stories[1]?.text()).toContain('Language: de.');
    expect(stories[0]?.get('.markdown h2').text()).toBe('One');
    expect(stories[1]?.get('.markdown h2').text()).toBe('Two');
    expect(stories.map((a) => a.get('details').attributes('open'))).toEqual([undefined, undefined]);
  });

  test('show the guide of a single deception open', async () => {
    const { wrapper } = await boot(server(), `/scenarios/${scenarioId}`);
    expect(wrapper.get('article.story details').attributes('open')).toBeDefined();
  });

  test('say so when the guides could not be loaded, and keep the deceptions', async () => {
    const { wrapper } = await boot(server('admin', { [`GET ${detail}/guide`]: () => failure(503, 'unavailable') }), `/scenarios/${scenarioId}`);
    expect(wrapper.text()).toContain('The guide could not be loaded.');
    expect(wrapper.get('article.story h3 a').text()).toBe('ssh-jump-host');
  });

  test('explain what to do next when there are none, to whoever may add one', async () => {
    for (const [role, text] of [
      ['admin', 'Add one to get honeytokens, files and a guide.'],
      ['viewer', 'No deception has joined this scenario.'],
    ] as const) {
      const s = server(role, { [`GET ${detail}`]: () => json(200, scenario()) });
      const { wrapper } = await boot(s, `/scenarios/${scenarioId}`);
      expect(wrapper.find('article.story').exists(), role).toBe(false);
      expect(wrapper.text(), role).toContain(text);
      expect(s.requests.some((r) => r.url.endsWith('/guide')), role).toBe(false);
      document.body.innerHTML = '';
    }
  });

  test('show a value of the persona and a name as text', async () => {
    const s = server('admin', { [`GET ${detail}`]: () => json(200, scenario({ deceptions: [joined('ssh-jump-host')], persona: { company: '<img src=x onerror=alert(1)>' } })) });
    const { wrapper } = await boot(s, `/scenarios/${scenarioId}`);
    expect(wrapper.find('dl.persona img').exists()).toBe(false);
    expect(wrapper.get('dl.persona bdi').text()).toBe('<img src=x onerror=alert(1)>');
  });
});

describe('the files of a scenario', () => {
  const lure = artifact({ id: artifactId, file_name: 'bookmarks.html', bindings: { portal: webToken.id } });
  const litter = artifact({ id: 'a11fac70-2222-4222-8333-944444444444', file_name: 'notes.txt', format: 'text', media_type: 'text/plain', bindings: {} });

  test('say in words whether each carries a honeytoken', async () => {
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/artifacts': () => json(200, { artifacts: [lure, litter] }) }), `/scenarios/${scenarioId}`);
    const rows = wrapper.findAll('.section').find((p) => p.find('h2').exists() && p.get('h2').text() === 'Files')?.findAll('tbody tr') ?? [];
    expect(rows.map((r) => [r.get('bdi').text(), r.findAll('td')[2]?.text()])).toEqual([
      ['bookmarks.html', 'Lure carrier'],
      ['notes.txt', 'Pocket litter'],
    ]);
  });

  test('explain what to do next when there are none', async () => {
    for (const [role, text] of [
      ['admin', 'Use "Add artifact" to add one from the catalog.'],
      ['viewer', 'None.'],
    ] as const) {
      const { wrapper } = await boot(server(role), `/scenarios/${scenarioId}`);
      expect(wrapper.text(), role).toContain(text);
      document.body.innerHTML = '';
    }
  });

  test('are extended by whoever may write, and by nobody else', async () => {
    for (const [role, offered] of [['admin', true], ['user', true], ['viewer', false]] as const) {
      const { wrapper } = await boot(server(role), `/scenarios/${scenarioId}`);
      expect(wrapper.find(`a[href="/scenarios/${scenarioId}/deceptions/new"]`).exists(), role).toBe(offered);
      expect(wrapper.find(`a[href="/scenarios/${scenarioId}/artifacts/new"]`).exists(), role).toBe(offered);
      document.body.innerHTML = '';
    }
  });

  test('cannot be extended on the pages of a viewer', async () => {
    for (const path of [`/scenarios/${scenarioId}/deceptions/new`, `/scenarios/${scenarioId}/artifacts/new`]) {
      const { router } = await boot(server('viewer'), path);
      await arrive(router, 'forbidden');
      document.body.innerHTML = '';
    }
  });
});

describe('adding a deception', () => {
  const path = `/scenarios/${scenarioId}/deceptions/new`;
  const add = `POST ${detail}/deceptions`;
  const added = () => json(201, { scenario: scenario(), honeytokens: [], artifacts: [] });

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
    expect(wrapper.text()).toContain('No deception is left to add.');
    expect(wrapper.find('form').exists()).toBe(false);
  });

  test('shows the value of the persona that the scenario has and cannot be changed, and asks for the others', async () => {
    const { wrapper } = await boot(server(), path);
    await choose(wrapper);
    const company = wrapper.get('#persona-company').element as HTMLInputElement;
    expect(company.value).toBe('Acme Corp');
    expect(company.readOnly).toBe(true);
    expect(wrapper.get('#persona-company-hint').text()).toContain('The scenario already has this value.');
    const host = wrapper.get('#persona-host').element as HTMLInputElement;
    expect(host.value).toBe('');
    expect(host.readOnly).toBe(false);
  });

  test('sends only the values the scenario lacks, the files that stayed chosen and the language', async () => {
    const s = server('admin', { [add]: added });
    const { wrapper, router } = await boot(s, path);
    await choose(wrapper);
    await wrapper.get('#guide-language').setValue('de');
    await type(wrapper, '#persona-host', ' portal.acme.example ');
    await submit(wrapper);
    expect(s.requests.find((r) => r.method === 'POST')?.body).toEqual({
      deception_id: 'browser-bookmarks',
      language: 'de',
      persona: { host: 'portal.acme.example' },
      artifacts: ['bookmarks'],
    });
    await arrive(router, 'scenario');
  });

  test('leaves out a file that was taken away', async () => {
    const s = server('admin', { [add]: added });
    const { wrapper } = await boot(s, path);
    await choose(wrapper);
    await wrapper.get('fieldset.files input[type=checkbox]').setValue(false);
    await type(wrapper, '#persona-host', 'portal.acme.example');
    await submit(wrapper);
    expect((s.requests.find((r) => r.method === 'POST')?.body as { artifacts: string[] }).artifacts).toEqual([]);
  });

  test('checks the values before it asks the server', async () => {
    const s = server('admin', { [add]: added });
    const { wrapper } = await boot(s, path);
    await choose(wrapper);
    await type(wrapper, '#persona-host', 'Portal_Host');
    await submit(wrapper);
    expect(wrapper.findAll('.problem').map((a) => a.text())).toEqual(['Portal host must be a host name of lowercase letters, digits, hyphens and dots.']);
    expect(s.requests.filter((r) => r.method === 'POST')).toHaveLength(0);
  });

  test('says that a value differs from the one of the scenario, without naming a value', async () => {
    const s = server('admin', { [add]: () => failure(409, 'persona_conflict') });
    const { wrapper } = await boot(s, path);
    await choose(wrapper);
    await type(wrapper, '#persona-host', 'portal.acme.example');
    await submit(wrapper);
    const alert = wrapper.get('[role=alert]').text();
    expect(alert).toContain('differs from the one that the scenario already has');
    expect(alert).not.toContain('Acme Corp');
    expect(alert).not.toContain('portal.acme.example');
    expect((wrapper.get('#persona-host').element as HTMLInputElement).value).toBe('portal.acme.example');
  });

  test('says why the server refused it', async () => {
    for (const [status, code, text] of [
      [409, 'deception_already_added', 'already part of the scenario'],
      [409, 'scenario_limit', 'as many deceptions or files as it can'],
      [422, 'dns_not_configured', 'NYKTUS_DNS_ZONES'],
      [422, 'artifact_reveals_decoy', 'reveal what it is'],
    ] as const) {
      const { wrapper } = await boot(server('admin', { [add]: () => failure(status, code) }), path);
      await choose(wrapper);
      await type(wrapper, '#persona-host', 'portal.acme.example');
      await submit(wrapper);
      expect(wrapper.get('[role=alert]').text(), code).toContain(text);
      expect(wrapper.find('form').exists(), code).toBe(true);
      document.body.innerHTML = '';
    }
  });

  test('says when the scenario does not exist', async () => {
    const { wrapper } = await boot(server('admin', { [`GET ${detail}`]: () => failure(404, 'not_found') }), path);
    expect(wrapper.get('[role=status]').text()).toBe('This does not exist.');
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

describe('adding an artifact', () => {
  const path = `/scenarios/${scenarioId}/artifacts/new`;
  const add = `POST ${detail}/artifacts`;
  const added = () => json(201, { scenario: scenario(), artifact: artifact() });

  async function choose(wrapper: Awaited<ReturnType<typeof boot>>['wrapper'], id = 'bookmarks') {
    await wrapper.get('#catalog-artifact').setValue(id);
    await flushPromises();
  }

  const optionTexts = (wrapper: Awaited<ReturnType<typeof boot>>['wrapper'], slot: string) => wrapper.findAll(`#slot-${slot} option`).map((o) => o.text());

  test('reads the honeytokens of the scenario, and only those', async () => {
    const s = server();
    await boot(s, path);
    expect(s.requests.find((r) => r.url.startsWith('/api/v1/honeytokens'))?.url).toContain(`scenario_id=${scenarioId}`);
  });

  test('offers only the honeytokens of a type that the slot accepts', async () => {
    const { wrapper } = await boot(server(), path);
    await choose(wrapper);
    expect(optionTexts(wrapper, 'portal')).toEqual(['Choose a honeytoken', '\u2068Portal link\u2069, Web URL']);
  });

  test('offers both types when the slot accepts both, and may stay empty when it is optional', async () => {
    const both = catalogArtifact({ slots: [{ key: 'portal', accepts: ['web_url', 'dns'], optional: true }] });
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/catalog/artifacts/bookmarks': () => json(200, both) }), path);
    await choose(wrapper);
    expect(optionTexts(wrapper, 'portal')).toEqual(['Leave empty', '\u2068Portal link\u2069, Web URL', '\u2068Portal name\u2069, DNS name']);
  });

  test('says in words whether the file becomes a lure carrier or pocket litter, as the slots are filled', async () => {
    const optional = catalogArtifact({ slots: [{ key: 'portal', accepts: ['web_url'], optional: true }] });
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/catalog/artifacts/bookmarks': () => json(200, optional) }), path);
    await choose(wrapper);
    expect(wrapper.get('.verdict').text()).toBe('Pocket litter. It carries no honeytoken. It makes the story believable and never raises an event itself.');
    await wrapper.get('#slot-portal').setValue(webToken.id);
    expect(wrapper.get('.verdict').text()).toBe('Lure carrier. It leads to a honeytoken of this scenario, so using what it names raises an event.');
    expect(wrapper.get('#slot-portal-hint').text()).toBe(`Leads to ${webToken.trigger_url}`);
    await wrapper.get('#slot-portal').setValue('');
    expect(wrapper.get('.verdict').text()).toContain('Pocket litter.');
  });

  test('says pocket litter for a file without a slot', async () => {
    const none = catalogArtifact({ slots: [] });
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/catalog/artifacts/bookmarks': () => json(200, none) }), path);
    await choose(wrapper);
    expect(wrapper.find('fieldset.slots').exists()).toBe(false);
    expect(wrapper.get('.verdict').text()).toContain('Pocket litter.');
  });

  test('sends the honeytoken for a bound slot and the values the scenario lacks, and shows the new file', async () => {
    const s = server('admin', { [add]: added, [`GET /api/v1/artifacts/${artifactId}`]: () => json(200, artifact()) });
    const { wrapper, router } = await boot(s, path);
    await choose(wrapper);
    await wrapper.get('#slot-portal').setValue(webToken.id);
    await wrapper.get('#placing-language').setValue('de');
    await type(wrapper, '#persona-host', 'portal.acme.example');
    await submit(wrapper);
    expect(s.requests.find((r) => r.method === 'POST')?.body).toEqual({
      catalog_artifact: 'bookmarks',
      language: 'de',
      persona: { host: 'portal.acme.example' },
      bindings: { portal: webToken.id },
    });
    await arrive(router, 'artifact');
  });

  test('sends no binding for an optional slot that stays empty', async () => {
    const optional = catalogArtifact({ slots: [{ key: 'portal', accepts: ['web_url'], optional: true }] });
    const s = server('admin', { 'GET /api/v1/catalog/artifacts/bookmarks': () => json(200, optional), [add]: added });
    const { wrapper } = await boot(s, path);
    await choose(wrapper);
    await type(wrapper, '#persona-host', 'portal.acme.example');
    await submit(wrapper);
    expect((s.requests.find((r) => r.method === 'POST')?.body as { bindings: object }).bindings).toEqual({});
  });

  test('asks for a honeytoken for a required slot before it asks the server', async () => {
    const s = server('admin', { [add]: added });
    const { wrapper } = await boot(s, path);
    await choose(wrapper);
    await type(wrapper, '#persona-host', 'portal.acme.example');
    await submit(wrapper);
    expect(wrapper.get('.problem').text()).toBe('Choose a honeytoken for the slot portal.');
    expect(s.requests.filter((r) => r.method === 'POST')).toHaveLength(0);
  });

  test('cannot be sent when no honeytoken of the scenario fits a required slot', async () => {
    const s = server('admin', { 'GET /api/v1/honeytokens': () => json(200, { honeytokens: [dnsToken] }) });
    const { wrapper } = await boot(s, path);
    await choose(wrapper);
    expect(wrapper.get('#slot-portal-hint').text()).toContain('no honeytoken of a type that this slot accepts');
    expect(wrapper.get('button[type=submit]').attributes('disabled')).toBeDefined();
  });

  test('shows a persona value of the scenario as it is, and does not send it', async () => {
    const s = server('admin', { [add]: added });
    const { wrapper } = await boot(s, path);
    await choose(wrapper);
    expect((wrapper.get('#persona-company').element as HTMLInputElement).value).toBe('Acme Corp');
    expect((wrapper.get('#persona-company').element as HTMLInputElement).readOnly).toBe(true);
    await wrapper.get('#slot-portal').setValue(webToken.id);
    await type(wrapper, '#persona-host', 'portal.acme.example');
    await submit(wrapper);
    expect((s.requests.find((r) => r.method === 'POST')?.body as { persona: object }).persona).toEqual({ host: 'portal.acme.example' });
  });

  test('says why the server refused it', async () => {
    for (const [status, code, text] of [
      [409, 'persona_conflict', 'differs from the one that the scenario already has'],
      [409, 'scenario_limit', 'as many deceptions or files as it can'],
      [422, 'artifact_reveals_decoy', 'reveal what it is'],
      [400, 'invalid_request', 'The input is not valid.'],
    ] as const) {
      const { wrapper } = await boot(server('admin', { [add]: () => failure(status, code) }), path);
      await choose(wrapper);
      await wrapper.get('#slot-portal').setValue(webToken.id);
      await type(wrapper, '#persona-host', 'portal.acme.example');
      await submit(wrapper);
      expect(wrapper.get('[role=alert]').text(), code).toContain(text);
      document.body.innerHTML = '';
    }
  });

  test('shows what was chosen last when the answers come in the other order', async () => {
    const answers: Record<string, (response: Response) => void> = {};
    const wait = (id: string) => () => new Promise<Response>((resolve) => (answers[id] = resolve)) as never;
    const s = server('admin', {
      'GET /api/v1/catalog/artifacts/bookmarks': wait('first'),
      'GET /api/v1/catalog/artifacts/notes': wait('second'),
    });
    const { wrapper } = await boot(s, path);
    await choose(wrapper, 'bookmarks');
    await choose(wrapper, 'notes');
    answers.second?.(json(200, catalogArtifact({ id: 'notes', summary: 'Chosen last.', slots: [] })));
    await flushPromises();
    answers.first?.(json(200, catalogArtifact({ summary: 'Chosen first.' })));
    await flushPromises();
    expect(wrapper.text()).toContain('Chosen last.');
    expect(wrapper.text()).not.toContain('Chosen first.');
  });

  test('says when the catalog has no artifact', async () => {
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/catalog/artifacts': () => json(200, { artifacts: [] }) }), path);
    expect(wrapper.text()).toContain('The catalog has no artifacts.');
  });
});
