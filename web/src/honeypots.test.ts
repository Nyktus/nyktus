// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises } from '@vue/test-utils';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { arrive, boot, submit, type } from './testing/boot';
import { failure, fakeServer, honeypot, honeypotConfig, honeypotId, honeypotSecret, json, noContent, sessionBody, withSecret } from './testing/fakeServer';

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = '';
  history.replaceState(null, '', '/');
});

type Role = 'admin' | 'user' | 'viewer';

function server(role: Role = 'admin', extra: Record<string, () => Response> = {}) {
  return fakeServer({
    'GET /api/v1/session': () => json(200, sessionBody(role)),
    'GET /api/v1/honeypots': () => json(200, { honeypots: [honeypot()] }),
    ...extra,
  });
}

const detail = `/api/v1/honeypots/${honeypotId}`;

describe('the list of honeypots', () => {
  test('shows the service, the status and the last report', async () => {
    const never = honeypot({ id: 'beefbeef-2222-4222-8333-944444444444', name: 'New LDAP', service: 'ldap', status: 'never', last_seen_at: null, sensor_version: null });
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/honeypots': () => json(200, { honeypots: [honeypot(), never] }) }), '/honeypots');
    const rows = wrapper.findAll('tbody tr');
    expect(rows[0]?.text()).toContain('Jump host');
    expect(rows[0]?.text()).toContain('SSH');
    expect(rows[0]?.text()).toContain('Online');
    expect(rows[0]?.get('time').attributes('title')).toBe('2026-10-22T07:55:00Z (UTC)');
    expect(rows[1]?.text()).toContain('LDAP');
    expect(rows[1]?.text()).toContain('No report');
    expect(rows[1]?.text()).toContain('No report yet');
  });

  test('asks for what the filters name', async () => {
    const s = server();
    const { wrapper } = await boot(s, '/honeypots');
    await wrapper.get('#filter-service').setValue('postgres');
    await flushPromises();
    await wrapper.get('#filter-state').setValue('true');
    await flushPromises();
    expect(s.requests.at(-1)?.url).toBe('/api/v1/honeypots?limit=50&service=postgres&enabled=true');
  });

  test('offers to create one to whoever may', async () => {
    for (const [role, offered] of [['admin', true], ['user', true], ['viewer', false]] as const) {
      const { wrapper } = await boot(server(role), '/honeypots');
      expect(wrapper.find('a[href="/honeypots/new"]').exists(), role).toBe(offered);
    }
  });

  test('is in the navigation', async () => {
    const { wrapper } = await boot(server('viewer'), '/honeypots');
    expect(wrapper.get('nav').text()).toContain('Honeypots');
  });

  test('cannot be created by a viewer', async () => {
    const s = server('viewer');
    const { router } = await boot(s, '/honeypots/new');
    await arrive(router, 'forbidden');
  });
});

describe('the secret of a new honeypot', () => {
  const created = () => json(201, withSecret(honeypot()), { 'Cache-Control': 'no-store' });

  async function make(s = server('admin', { 'POST /api/v1/honeypots': created, [`GET ${detail}`]: () => json(200, honeypot({ status: 'never', last_seen_at: null })) })) {
    const app = await boot(s, '/honeypots/new');
    await type(app.wrapper, '#name', '  Jump host  ');
    await type(app.wrapper, '#techniques', 'T1078');
    await app.wrapper.get('#service').setValue('ssh');
    await submit(app.wrapper);
    return { ...app, s };
  }

  test('sends what was entered, with the default severity left to the server', async () => {
    const { s } = await make();
    expect(s.requests.find((r) => r.method === 'POST')?.body).toEqual({
      service: 'ssh',
      name: 'Jump host',
      notes: '',
      enabled: true,
      techniques: ['T1078'],
    });
  });

  test('asks for a name that is more than spaces, before it asks the server', async () => {
    const s = server('admin', { 'POST /api/v1/honeypots': created });
    const { wrapper } = await boot(s, '/honeypots/new');
    await type(wrapper, '#name', '   ');
    await submit(wrapper);
    expect(wrapper.get('#name-problem').text()).toBe('Enter a name.');
    expect(s.requests.filter((r) => r.method === 'POST')).toHaveLength(0);
  });

  test('is shown once, with the entry for the configuration of the sensor', async () => {
    const { wrapper } = await make();
    expect(wrapper.get('[role=region]').text()).toContain(honeypotSecret);
    expect(wrapper.get('pre').text()).toBe(honeypotConfig.trimEnd());
    expect(wrapper.text()).toContain('This is the only time the secret is shown.');
  });

  test('is gone once the user says that they copied it', async () => {
    const { wrapper } = await make();
    await wrapper.get('[role=region] button.button-primary').trigger('click');
    expect(wrapper.html()).not.toContain(honeypotSecret);
    expect(wrapper.find('[role=region]').exists()).toBe(false);
  });

  // The state of the page is what scripts of the console can read, so the secret is out of it, not only out of the picture.
  test('is gone from the state of the page once the user says that they copied it', async () => {
    const { wrapper } = await make();
    const state = () => wrapper.findComponent({ name: 'HoneypotNewView' }).vm as unknown as { once: unknown; createdId: unknown };
    expect(JSON.stringify(state().once)).toContain(honeypotSecret);
    await wrapper.get('[role=region] button.button-primary').trigger('click');
    expect(state().once).toBeUndefined();
    expect(JSON.stringify(state())).not.toContain(honeypotSecret);
  });

  test('is gone when the user leaves, and the page that they go to does not have it', async () => {
    const { wrapper, router } = await make();
    await wrapper.get('a.button-primary').trigger('click');
    await arrive(router, 'honeypot');
    expect(wrapper.html()).not.toContain(honeypotSecret);
    expect(wrapper.find('[role=region]').exists()).toBe(false);
  });

  // The secret must not outlive the page in any place that scripts or the browser keep.
  test('is kept nowhere: not in the address, the history, the storage or a request', async () => {
    const { s, router, wrapper } = await make();
    const everything = JSON.stringify([
      globalThis.location.href,
      history.state,
      router.currentRoute.value,
      Object.entries(localStorage),
      Object.entries(sessionStorage),
      document.cookie,
      s.requests.map((r) => r.url),
      s.requests.filter((r) => r.method !== 'POST').map((r) => r.body),
    ]);
    expect(everything).not.toContain(honeypotSecret);
    // The one place that holds it is the page, and that is what the user is asked to copy from.
    expect(wrapper.html()).toContain(honeypotSecret);
  });

  test('is not shown when the server refuses', async () => {
    const { wrapper } = await make(server('admin', { 'POST /api/v1/honeypots': () => failure(400, 'invalid_request') }));
    expect(wrapper.find('[role=region]').exists()).toBe(false);
    expect(wrapper.get('[role=alert]').text()).toBe('The input is not valid.');
    expect(wrapper.find('form').exists()).toBe(true);
  });
});

describe('a honeypot', () => {
  const one = (h = honeypot(), extra: Record<string, () => Response> = {}) => server('admin', { [`GET ${detail}`]: () => json(200, h), ...extra });
  const path = `/honeypots/${honeypotId}`;

  test('shows its status and what the sensor last reported', async () => {
    const { wrapper } = await boot(one(), path);
    expect(wrapper.get('h1').text()).toBe('Jump host');
    expect(wrapper.text()).toContain('Online');
    expect(wrapper.text()).toContain('0.1.0');
    expect(wrapper.get('.notes').text()).toBe('VLAN 20, rack 4');
  });

  test('has no secret and offers none to read', async () => {
    const { wrapper } = await boot(one(), path);
    expect(wrapper.find('[role=region]').exists()).toBe(false);
    expect(wrapper.html()).not.toContain('secret:');
  });

  test('shows a name that is markup as text', async () => {
    const { wrapper } = await boot(one(honeypot({ name: '<img src=x onerror=alert(1)>', notes: '<b>x</b>' })), path);
    expect(wrapper.find('img[src=x]').exists()).toBe(false);
    expect(wrapper.find('b').exists()).toBe(false);
  });

  test('is only read by a viewer', async () => {
    const s = fakeServer({ 'GET /api/v1/session': () => json(200, sessionBody('viewer')), [`GET ${detail}`]: () => json(200, honeypot()) });
    const { wrapper } = await boot(s, path);
    expect(wrapper.find('form').exists()).toBe(false);
    expect(wrapper.findAll('button').map((b) => b.text())).toEqual(['Sign out']);
  });

  test('cannot change its service', async () => {
    const { wrapper } = await boot(one(), path);
    expect(wrapper.get('#service').attributes('disabled')).toBeDefined();
  });

  test('sends only what changed', async () => {
    const s = one(honeypot(), { [`PATCH ${detail}`]: () => json(200, honeypot({ name: 'Renamed', updated_at: '2026-10-22T10:00:00Z' })) });
    const { wrapper } = await boot(s, path);
    await type(wrapper, '#name', 'Renamed');
    await submit(wrapper);
    expect(s.requests.find((r) => r.method === 'PATCH')?.body).toEqual({ name: 'Renamed' });
    expect(wrapper.get('h1').text()).toBe('Renamed');
  });

  test('leaves out what it did not change, also the name', async () => {
    const s = one(honeypot(), { [`PATCH ${detail}`]: () => json(200, honeypot({ notes: 'Moved', enabled: false, severity: 'critical', techniques: [] })) });
    const { wrapper } = await boot(s, path);
    await type(wrapper, '#notes', 'Moved');
    await wrapper.get('#enabled').setValue(false);
    await wrapper.get('#severity').setValue('critical');
    await type(wrapper, '#techniques', '');
    await submit(wrapper);
    expect(s.requests.find((r) => r.method === 'PATCH')?.body).toEqual({ notes: 'Moved', enabled: false, severity: 'critical', techniques: [] });
  });

  describe('with a replaced secret', () => {
    async function ask(extra: Record<string, () => Response> = {}) {
      const s = one(honeypot(), { [`POST ${detail}/secret`]: () => json(200, withSecret(honeypot()), { 'Cache-Control': 'no-store' }), ...extra });
      const app = await boot(s, path);
      await app.wrapper.findAll('button').find((b) => b.text() === 'Replace the secret')!.trigger('click');
      await flushPromises();
      return { ...app, s };
    }

    test('asks first, and says what it costs', async () => {
      const { wrapper, s } = await ask();
      expect(wrapper.find('dialog[open]').exists()).toBe(true);
      expect(wrapper.get('dialog[open]').text()).toContain('shut out until you configure it with the new one');
      expect(s.requests.filter((r) => r.method === 'POST')).toHaveLength(0);
    });

    test('does nothing when the user cancels', async () => {
      const { wrapper, s } = await ask();
      await wrapper.get('dialog .button-ghost').trigger('click');
      await flushPromises();
      expect(s.requests.filter((r) => r.method === 'POST')).toHaveLength(0);
      expect(wrapper.html()).not.toContain(honeypotSecret);
    });

    test('shows the new secret once, with the status reset', async () => {
      const { wrapper } = await ask();
      await wrapper.get('dialog .danger').trigger('click');
      await flushPromises();
      expect(wrapper.get('[role=region]').text()).toContain(honeypotSecret);
      expect(wrapper.get('.badges').text()).toContain('No report');
      await wrapper.get('[role=region] button.button-primary').trigger('click');
      expect(wrapper.html()).not.toContain(honeypotSecret);
    });

    // The record of the honeypot that the page keeps is what a later change sends from; it never holds the secret.
    test('is not part of the record that the page keeps, nor of the state after the user is done', async () => {
      const { wrapper } = await ask();
      await wrapper.get('dialog .danger').trigger('click');
      await flushPromises();
      const state = () => wrapper.findComponent({ name: 'HoneypotView' }).vm as unknown as { honeypot: unknown; once: unknown };
      expect(JSON.stringify(state().honeypot)).not.toContain(honeypotSecret);
      expect(JSON.stringify(state().honeypot)).not.toContain('sensor_config');
      expect(JSON.stringify(state().once)).toContain(honeypotSecret);
      await wrapper.get('[role=region] button.button-primary').trigger('click');
      expect(state().once).toBeUndefined();
      expect(JSON.stringify(state())).not.toContain(honeypotSecret);
    });

    test('is kept nowhere else', async () => {
      const { wrapper, router } = await ask();
      await wrapper.get('dialog .danger').trigger('click');
      await flushPromises();
      expect(JSON.stringify([globalThis.location.href, history.state, router.currentRoute.value, Object.entries(localStorage), Object.entries(sessionStorage)])).not.toContain(
        honeypotSecret,
      );
    });

    test('says so when the server refuses, and shows no secret', async () => {
      const { wrapper } = await ask({ [`POST ${detail}/secret`]: () => failure(503, 'unavailable') });
      await wrapper.get('dialog .danger').trigger('click');
      await flushPromises();
      expect(wrapper.get('[role=alert]').text()).toBe('The server is busy. Try again in a moment.');
      expect(wrapper.find('[role=region]').exists()).toBe(false);
    });
  });

  describe('deleted', () => {
    test('only after the user confirms', async () => {
      const s = one(honeypot(), { [`DELETE ${detail}`]: noContent });
      const { wrapper, router } = await boot(s, path);
      await wrapper.findAll('button').find((b) => b.text() === 'Delete')!.trigger('click');
      await flushPromises();
      expect(wrapper.get('dialog[open] h2').text()).toBe('Delete this honeypot?');
      expect(s.requests.filter((r) => r.method === 'DELETE')).toHaveLength(0);
      await wrapper.get('dialog[open] .danger').trigger('click');
      await flushPromises();
      await arrive(router, 'honeypots');
      expect(s.requests.filter((r) => r.method === 'DELETE')).toHaveLength(1);
    });
  });

  test('says when it does not exist', async () => {
    const { wrapper } = await boot(one(honeypot(), { [`GET ${detail}`]: () => failure(404, 'not_found') }), path);
    expect(wrapper.get('[role=status]').text()).toBe('This does not exist.');
  });
});
