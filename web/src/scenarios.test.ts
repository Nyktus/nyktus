// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises } from '@vue/test-utils';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { arrive, boot, submit, type } from './testing/boot';
import { failure, fakeServer, honeypot, honeypotId, honeytoken, json, noContent, scenario, scenarioId, sessionBody } from './testing/fakeServer';

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = '';
  history.replaceState(null, '', '/');
});

type Role = 'admin' | 'user' | 'viewer';

const detail = `/api/v1/scenarios/${scenarioId}`;
const htPath = '/api/v1/honeytokens/c0ffee00-1111-4222-8333-944444444444';

function server(role: Role = 'admin', extra: Record<string, () => Response> = {}) {
  return fakeServer({
    'GET /api/v1/session': () => json(200, sessionBody(role)),
    'GET /api/v1/scenarios': () => json(200, { scenarios: [scenario()] }),
    [`GET ${detail}`]: () => json(200, scenario()),
    'GET /api/v1/honeytokens': () => json(200, { honeytokens: [] }),
    'GET /api/v1/artifacts': () => json(200, { artifacts: [] }),
    'GET /api/v1/honeypots': () => json(200, { honeypots: [] }),
    ...extra,
  });
}

describe('the list of scenarios', () => {
  test('shows where each came from', async () => {
    const fromCatalog = scenario({ id: 'dec0de00-2222-4222-8333-944444444444', name: 'SSH jump host', deception_id: 'ssh-jump-host', language: 'en', persona: { host: 'jump02' } });
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/scenarios': () => json(200, { scenarios: [scenario(), fromCatalog] }) }), '/scenarios');
    const rows = wrapper.findAll('tbody tr');
    expect(rows[0]?.text()).toContain('Put together by hand');
    expect(rows[1]?.text()).toContain('From the deception ssh-jump-host');
    expect(rows[0]?.get('a').attributes('href')).toBe(`/scenarios/${scenarioId}`);
  });

  test('says when there are none', async () => {
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/scenarios': () => json(200, { scenarios: [] }) }), '/scenarios');
    expect(wrapper.text()).toContain('There are no scenarios yet.');
  });

  test('offers to create one to whoever may, and is in the navigation of everyone', async () => {
    for (const [role, offered] of [['admin', true], ['user', true], ['viewer', false]] as const) {
      const { wrapper } = await boot(server(role), '/scenarios');
      expect(wrapper.find('a[href="/scenarios/new"]').exists(), role).toBe(offered);
      expect(wrapper.get('nav').text()).toContain('Scenarios');
    }
  });

  test('is not opened for creating by a viewer', async () => {
    const { router } = await boot(server('viewer'), '/scenarios/new');
    await arrive(router, 'forbidden');
  });
});

describe('creating a scenario', () => {
  test('sends what was entered and shows the new scenario', async () => {
    const s = server('admin', { 'POST /api/v1/scenarios': () => json(201, scenario()) });
    const { wrapper, router } = await boot(s, '/scenarios/new');
    await type(wrapper, '#name', '  Stolen backup  ');
    await type(wrapper, '#notes', 'A backup.');
    await type(wrapper, '#engage', 'eac0005, EAC0006 EAC0005');
    await submit(wrapper);
    expect(s.requests.find((r) => r.method === 'POST')?.body).toEqual({ name: 'Stolen backup', notes: 'A backup.', engage_activities: ['EAC0005', 'EAC0006'] });
    await arrive(router, 'scenario');
  });

  test('asks for a name that is more than spaces, before it asks the server', async () => {
    const s = server('admin', { 'POST /api/v1/scenarios': () => json(201, scenario()) });
    const { wrapper } = await boot(s, '/scenarios/new');
    await type(wrapper, '#name', '   ');
    await submit(wrapper);
    expect(wrapper.get('#name-problem').text()).toBe('Enter a name.');
    expect(s.requests.filter((r) => r.method === 'POST')).toHaveLength(0);
  });

  test('does not send Engage identifiers that are none, and says which', async () => {
    const s = server();
    const { wrapper } = await boot(s, '/scenarios/new');
    await type(wrapper, '#name', 'x');
    await type(wrapper, '#engage', 'EAC0005, T1078');
    await submit(wrapper);
    expect(wrapper.text()).toContain('These are not Engage activity identifiers: T1078');
    expect(s.requests.filter((r) => r.method === 'POST')).toHaveLength(0);
  });

  test('keeps the form for a failure', async () => {
    const { wrapper } = await boot(server('admin', { 'POST /api/v1/scenarios': () => failure(400, 'invalid_request') }), '/scenarios/new');
    await type(wrapper, '#name', 'Keep me');
    await submit(wrapper);
    expect(wrapper.get('[role=alert]').text()).toBe('The input is not valid.');
    expect((wrapper.get('#name').element as HTMLInputElement).value).toBe('Keep me');
  });
});

describe('a scenario', () => {
  const path = `/scenarios/${scenarioId}`;

  test('shows its story, its source and what it carries out', async () => {
    const { wrapper } = await boot(server(), path);
    expect(wrapper.get('h1').text()).toBe('Stolen backup');
    expect(wrapper.get('.notes').text()).toBe('A backup that someone left on a share.');
    expect(wrapper.text()).toContain('EAC0005');
  });

  test('shows the persona that a deception was applied with, as text', async () => {
    const s = server('admin', { [`GET ${detail}`]: () => json(200, scenario({ deception_id: 'ssh-jump-host', language: 'de', persona: { host: '<b>jump02</b>' } })) });
    const { wrapper } = await boot(s, path);
    expect(wrapper.get('.persona').text()).toContain('<b>jump02</b>');
    expect(wrapper.find('.persona b').exists()).toBe(false);
  });

  test('lists its honeytokens and honeypots, asking for those of the scenario', async () => {
    const s = server('admin', {
      'GET /api/v1/honeytokens': () => json(200, { honeytokens: [honeytoken({ scenario_id: scenarioId })] }),
      'GET /api/v1/honeypots': () => json(200, { honeypots: [honeypot({ scenario_id: scenarioId })] }),
    });
    const { wrapper } = await boot(s, path);
    expect(wrapper.text()).toContain('Backup share link');
    expect(wrapper.text()).toContain('Jump host');
    expect(s.requests.map((r) => r.url)).toContain(`/api/v1/honeytokens?limit=50&scenario_id=${scenarioId}`);
    expect(s.requests.map((r) => r.url)).toContain(`/api/v1/honeypots?limit=50&scenario_id=${scenarioId}`);
  });

  test('says when it has none', async () => {
    const { wrapper } = await boot(server(), path);
    expect(wrapper.findAll('.hint').filter((h) => h.text().startsWith('None yet')).length).toBe(2);
  });

  test('removes a honeytoken from itself, which then stands alone', async () => {
    let listed = true;
    const s = server('admin', {
      'GET /api/v1/honeytokens': () => json(200, { honeytokens: listed ? [honeytoken({ scenario_id: scenarioId })] : [] }),
      [`DELETE ${htPath}/scenario`]: () => {
        listed = false;
        return json(200, honeytoken());
      },
    });
    const { wrapper } = await boot(s, path);
    await wrapper.findAll('button').find((b) => b.text() === 'Remove from scenario')!.trigger('click');
    await flushPromises();
    expect(s.requests.filter((r) => r.method === 'DELETE')).toHaveLength(1);
    expect(wrapper.text()).not.toContain('Backup share link');
  });

  test('removes a honeytoken once, however often the button is pressed', async () => {
    let answer: (response: Response) => void = () => undefined;
    const s = server('admin', {
      'GET /api/v1/honeytokens': () => json(200, { honeytokens: [honeytoken({ scenario_id: scenarioId })] }),
      [`DELETE ${htPath}/scenario`]: () => new Promise<Response>((resolve) => (answer = resolve)) as never,
    });
    const { wrapper } = await boot(s, path);
    const button = wrapper.findAll('button').find((b) => b.text() === 'Remove from scenario')!;
    await button.trigger('click');
    await button.trigger('click');
    answer(json(200, honeytoken()));
    await flushPromises();
    expect(s.requests.filter((r) => r.method === 'DELETE')).toHaveLength(1);
  });

  test('is only read by a viewer', async () => {
    const s = server('viewer', { 'GET /api/v1/honeytokens': () => json(200, { honeytokens: [honeytoken({ scenario_id: scenarioId })] }) });
    const { wrapper } = await boot(s, path);
    expect(wrapper.find('form').exists()).toBe(false);
    // The frame has two buttons of its own: the one that opens the menu on a narrow screen, and the sign-out.
    expect(wrapper.findAll('button').map((b) => b.text())).toEqual(['Menu', 'Sign out']);
  });

  test('sends only what changed', async () => {
    const s = server('admin', { [`PATCH ${detail}`]: () => json(200, scenario({ notes: 'Moved', updated_at: '2026-10-22T10:00:00Z' })) });
    const { wrapper } = await boot(s, path);
    await type(wrapper, '#notes', 'Moved');
    await submit(wrapper);
    expect(s.requests.find((r) => r.method === 'PATCH')?.body).toEqual({ notes: 'Moved' });
    expect(wrapper.text()).toContain('Saved.');
  });

  test('says when it does not exist', async () => {
    const { wrapper } = await boot(server('admin', { [`GET ${detail}`]: () => failure(404, 'not_found') }), path);
    expect(wrapper.get('[role=status]').text()).toBe('This does not exist.');
  });

  describe('deleted', () => {
    async function ask(role: Role = 'admin') {
      const s = server(role, { [`DELETE ${detail}`]: noContent });
      const app = await boot(s, path);
      await app.wrapper.findAll('button').find((b) => b.text() === 'Delete')!.trigger('click');
      await flushPromises();
      return { ...app, s };
    }

    test('keeps the decoys unless the user says otherwise', async () => {
      const { wrapper, router, s } = await ask();
      expect(wrapper.find('dialog[open]').exists()).toBe(true);
      await wrapper.get('dialog[open] .danger').trigger('click');
      await flushPromises();
      expect(s.requests.find((r) => r.method === 'DELETE')?.url).toBe(detail);
      await arrive(router, 'scenarios');
    });

    test('deletes the decoys that the user chose, and only those', async () => {
      const { wrapper, s } = await ask();
      await wrapper.get('input[name="delete-honeytokens"][value="delete"]').setValue(true);
      await wrapper.get('input[name="delete-artifacts"][value="delete"]').setValue(true);
      await wrapper.get('dialog[open] .danger').trigger('click');
      await flushPromises();
      expect(s.requests.find((r) => r.method === 'DELETE')?.url).toBe(`${detail}?honeytokens=delete&artifacts=delete`);
    });

    // A choice to delete that was given up must not come back with the next click on "Delete".
    test('starts with keeping again after the user cancelled with a choice to delete', async () => {
      const { wrapper, s } = await ask();
      await wrapper.get('input[name="delete-honeytokens"][value="delete"]').setValue(true);
      await wrapper.get('dialog[open] .button-ghost').trigger('click');
      await flushPromises();
      await wrapper.findAll('button').find((b) => b.text() === 'Delete' && b.element.closest('dialog') === null)!.trigger('click');
      await flushPromises();
      expect((wrapper.get('input[name="delete-honeytokens"][value="keep"]').element as HTMLInputElement).checked).toBe(true);
      await wrapper.get('dialog[open] .danger').trigger('click');
      await flushPromises();
      expect(s.requests.find((r) => r.method === 'DELETE')?.url).toBe(detail);
    });

    test('starts with keeping again after the server refused a choice to delete', async () => {
      const { wrapper, s } = await ask();
      s.on(`DELETE ${detail}`, () => failure(503, 'unavailable'));
      await wrapper.get('input[name="delete-artifacts"][value="delete"]').setValue(true);
      await wrapper.get('dialog[open] .danger').trigger('click');
      await flushPromises();
      s.on(`DELETE ${detail}`, noContent);
      await wrapper.findAll('button').find((b) => b.text() === 'Delete' && b.element.closest('dialog') === null)!.trigger('click');
      await flushPromises();
      await wrapper.get('dialog[open] .danger').trigger('click');
      await flushPromises();
      expect(s.requests.filter((r) => r.method === 'DELETE').at(-1)?.url).toBe(detail);
    });

    test('asks for the honeypots to be deleted only when the user chose it', async () => {
      const { wrapper, s } = await ask();
      await wrapper.get('input[name="delete-honeypots"][value="delete"]').setValue(true);
      await wrapper.get('dialog[open] .danger').trigger('click');
      await flushPromises();
      expect(s.requests.find((r) => r.method === 'DELETE')?.url).toBe(`${detail}?honeypots=delete`);
    });

    test('does nothing when the user cancels', async () => {
      const { wrapper, s } = await ask();
      await wrapper.get('dialog[open] .button-ghost').trigger('click');
      await flushPromises();
      expect(s.requests.filter((r) => r.method === 'DELETE')).toHaveLength(0);
    });

    test('is not offered to a viewer', async () => {
      const s = server('viewer');
      const { wrapper } = await boot(s, path);
      expect(wrapper.find('dialog').exists()).toBe(false);
    });

    test('says so when the server refuses', async () => {
      const { wrapper, s } = await ask();
      s.on(`DELETE ${detail}`, () => failure(403, 'forbidden'));
      await wrapper.get('dialog[open] .danger').trigger('click');
      await flushPromises();
      expect(wrapper.get('[role=alert]').text()).toBe('You are not allowed to do this.');
    });
  });
});

describe('the scenario of a honeytoken', () => {
  const path = '/honeytokens/c0ffee00-1111-4222-8333-944444444444';
  const two = scenario({ id: 'dec0de00-2222-4222-8333-944444444444', name: 'Other story' });

  function ht(role: Role, h = honeytoken(), extra: Record<string, () => Response> = {}) {
    return server(role, {
      [`GET ${htPath}`]: () => json(200, h),
      'GET /api/v1/scenarios': () => json(200, { scenarios: [scenario(), two] }),
      ...extra,
    });
  }

  test('can be chosen, and is then shown by name', async () => {
    const s = ht('admin', honeytoken(), { [`PUT ${htPath}/scenario`]: () => json(200, honeytoken({ scenario_id: scenarioId })) });
    const { wrapper } = await boot(s, path);
    expect(wrapper.text()).toContain('Stands alone');
    await wrapper.get('#scenario-honeytoken').setValue(scenarioId);
    await wrapper.get('.assign-form').trigger('submit');
    await flushPromises();
    expect(s.requests.find((r) => r.method === 'PUT')?.body).toEqual({ scenario_id: scenarioId });
    expect(wrapper.get('.assign a').text()).toBe('Stolen backup');
    expect(wrapper.get('.assign a').attributes('href')).toBe(`/scenarios/${scenarioId}`);
  });

  test('is shown by name, and can be removed from it', async () => {
    const s = ht('admin', honeytoken({ scenario_id: scenarioId }), { [`DELETE ${htPath}/scenario`]: () => json(200, honeytoken()) });
    const { wrapper } = await boot(s, path);
    expect(wrapper.get('.assign a').text()).toBe('Stolen backup');
    await wrapper.findAll('.assign button').find((b) => b.text() === 'Remove from scenario')!.trigger('click');
    await flushPromises();
    expect(wrapper.text()).toContain('Stands alone');
  });

  test('says when the server refuses, and keeps what it shows', async () => {
    const s = ht('admin', honeytoken(), { [`PUT ${htPath}/scenario`]: () => failure(409, 'honeytoken_in_scenario') });
    const { wrapper } = await boot(s, path);
    await wrapper.get('#scenario-honeytoken').setValue(scenarioId);
    await wrapper.get('.assign-form').trigger('submit');
    await flushPromises();
    expect(wrapper.get('.assign [role=alert]').text()).toContain('conflicts with the current state');
    expect(wrapper.text()).toContain('Stands alone');
  });

  test('is only read by a viewer', async () => {
    const { wrapper } = await boot(ht('viewer', honeytoken({ scenario_id: scenarioId })), path);
    expect(wrapper.get('.assign a').text()).toBe('Stolen backup');
    expect(wrapper.find('.assign button').exists()).toBe(false);
    expect(wrapper.find('.assign-form').exists()).toBe(false);
  });

  test('does not ask for the scenarios to choose from when the user may not choose', async () => {
    const s = ht('viewer');
    await boot(s, path);
    expect(s.requests.filter((r) => r.url.startsWith('/api/v1/scenarios'))).toHaveLength(0);
  });

  test('does not say that there are no scenarios when the list could not be read', async () => {
    const s = ht('admin', honeytoken(), { 'GET /api/v1/scenarios': () => failure(503, 'unavailable') });
    const { wrapper } = await boot(s, path);
    expect(wrapper.get('.assign [role=alert]').text()).toBe('The server is busy. Try again in a moment.');
    expect(wrapper.text()).not.toContain('There are no scenarios yet.');
  });

  test('says that it offers only the first scenarios when there are more than it reads', async () => {
    const s = ht('admin', honeytoken(), { 'GET /api/v1/scenarios': () => json(200, { scenarios: [scenario()], next_cursor: 'more' }) });
    const { wrapper } = await boot(s, path);
    expect(s.requests.filter((r) => r.url.startsWith('/api/v1/scenarios'))).toHaveLength(10);
    expect(wrapper.get('.assign').text()).toContain('Only the first 10 scenarios are offered.');
  });

  test('offers no choice when there is no scenario', async () => {
    const s = ht('admin', honeytoken(), { 'GET /api/v1/scenarios': () => json(200, { scenarios: [] }) });
    const { wrapper } = await boot(s, path);
    expect(wrapper.find('.assign-form').exists()).toBe(false);
    expect(wrapper.text()).toContain('There are no scenarios yet.');
  });
});

describe('the scenario of a honeypot', () => {
  const hpPath = `/api/v1/honeypots/${honeypotId}`;

  test('can be chosen with the permission of honeypots', async () => {
    const s = server('admin', {
      [`GET ${hpPath}`]: () => json(200, honeypot()),
      [`PUT ${hpPath}/scenario`]: () => json(200, honeypot({ scenario_id: scenarioId })),
    });
    const { wrapper } = await boot(s, `/honeypots/${honeypotId}`);
    await wrapper.get('#scenario-honeypot').setValue(scenarioId);
    await wrapper.get('.assign-form').trigger('submit');
    await flushPromises();
    expect(s.requests.find((r) => r.method === 'PUT')?.url).toBe(`${hpPath}/scenario`);
    expect(wrapper.get('.assign a').text()).toBe('Stolen backup');
  });
});
