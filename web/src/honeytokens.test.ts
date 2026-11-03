// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises } from '@vue/test-utils';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { arrive, boot, submit, type } from './testing/boot';
import { failure, fakeServer, honeytoken, json, noContent, scenario, scenarioId, sessionBody } from './testing/fakeServer';

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = '';
  history.replaceState(null, '', '/');
});

type Role = 'admin' | 'user' | 'viewer';

function server(role: Role = 'admin', extra: Record<string, () => Response> = {}) {
  return fakeServer({
    'GET /api/v1/session': () => json(200, sessionBody(role)),
    'GET /api/v1/honeytokens': () => json(200, { honeytokens: [honeytoken()] }),
    'GET /api/v1/scenarios': () => json(200, { scenarios: [] }),
    ...extra,
  });
}

const other = honeytoken({
  id: 'c0ffee00-2222-4222-8333-944444444444',
  name: 'Staging DNS',
  type: 'dns',
  trigger_url: null,
  trigger_names: ['abcdefghijklmnopqrstuvwxyz.t.example.net', 'abcdefghijklmnopqrstuvwxyz.t.example.org'],
  enabled: false,
  severity: 'low',
});

describe('the list of honeytokens', () => {
  test('shows what the server lists', async () => {
    const { wrapper } = await boot(
      server('admin', { 'GET /api/v1/honeytokens': () => json(200, { honeytokens: [honeytoken(), other] }) }),
      '/honeytokens',
    );
    const rows = wrapper.findAll('tbody tr');
    expect(rows).toHaveLength(2);
    expect(rows[0]?.text()).toContain('Backup share link');
    expect(rows[0]?.text()).toContain('Web URL');
    expect(rows[0]?.text()).toContain('Enabled');
    expect(rows[0]?.text()).toContain('High');
    expect(rows[1]?.text()).toContain('DNS name');
    expect(rows[1]?.text()).toContain('Disabled');
    expect(rows[0]?.get('a').attributes('href')).toBe('/honeytokens/c0ffee00-1111-4222-8333-944444444444');
  });

  test('shows a name that is markup as text', async () => {
    const { wrapper } = await boot(
      server('admin', { 'GET /api/v1/honeytokens': () => json(200, { honeytokens: [honeytoken({ name: '<img src=x onerror=alert(1)>' })] }) }),
      '/honeytokens',
    );
    expect(wrapper.find('img[src=x]').exists()).toBe(false);
    expect(wrapper.get('tbody a').text()).toBe('<img src=x onerror=alert(1)>');
  });

  test('says so when there are none, and when the filter finds none', async () => {
    const s = server('admin', { 'GET /api/v1/honeytokens': () => json(200, { honeytokens: [] }) });
    const { wrapper } = await boot(s, '/honeytokens');
    expect(wrapper.text()).toContain('There are no honeytokens yet.');
    await wrapper.get('#filter-type').setValue('dns');
    await flushPromises();
    expect(wrapper.text()).toContain('No honeytokens found.');
  });

  test('asks for what the filters name, and starts again from the first page', async () => {
    const s = server();
    const { wrapper } = await boot(s, '/honeytokens');
    await wrapper.get('#filter-type').setValue('web_image');
    await flushPromises();
    await wrapper.get('#filter-state').setValue('false');
    await flushPromises();
    expect(s.requests.map((r) => r.url).filter((u) => u.startsWith('/api/v1/honeytokens'))).toEqual([
      '/api/v1/honeytokens?limit=50',
      '/api/v1/honeytokens?limit=50&type=web_image',
      '/api/v1/honeytokens?limit=50&type=web_image&enabled=false',
    ]);
  });

  test('loads the next page with the cursor', async () => {
    const s = server('admin', {
      'GET /api/v1/honeytokens': (() => {
        let calls = 0;
        return () => (++calls === 1 ? json(200, { honeytokens: [honeytoken()], next_cursor: 'cursor-1' }) : json(200, { honeytokens: [other] }));
      })(),
    });
    const { wrapper } = await boot(s, '/honeytokens');
    await wrapper.get('.more button').trigger('click');
    await flushPromises();
    expect(wrapper.findAll('tbody tr')).toHaveLength(2);
    expect(s.requests.at(-1)?.url).toBe('/api/v1/honeytokens?limit=50&cursor=cursor-1');
    expect(wrapper.find('.more').exists()).toBe(false);
  });

  test('says when the list could not be loaded', async () => {
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/honeytokens': () => failure(503, 'unavailable') }), '/honeytokens');
    expect(wrapper.get('[role=alert]').text()).toContain('The honeytokens could not be loaded.');
  });

  test('offers an administrator and a user to create one, and a viewer not', async () => {
    for (const [role, offered] of [['admin', true], ['user', true], ['viewer', false]] as const) {
      const { wrapper } = await boot(server(role), '/honeytokens');
      expect(wrapper.find('a[href="/honeytokens/new"]').exists(), role).toBe(offered);
    }
  });

  test('is in the navigation of every role', async () => {
    const { wrapper } = await boot(server('viewer'), '/honeytokens');
    expect(wrapper.get('nav').text()).toContain('Honeytokens');
  });
});

describe('a page that the role may not open', () => {
  test('is not opened, and no request is sent for it', async () => {
    const s = server('viewer');
    const { wrapper, router } = await boot(s, '/honeytokens/new');
    await arrive(router, 'forbidden');
    expect(wrapper.get('h1').text()).toBe('Not allowed');
    expect(s.requests.map((r) => r.url)).toEqual(['/api/v1/session']);
  });
});

describe('creating a honeytoken', () => {
  async function open(s = server()) {
    const app = await boot(s, '/honeytokens/new');
    return { ...app, s };
  }

  test('sends what was entered and shows the new honeytoken', async () => {
    const s = server('admin', {
      'POST /api/v1/honeytokens': () => json(201, honeytoken()),
      'GET /api/v1/honeytokens/c0ffee00-1111-4222-8333-944444444444': () => json(200, honeytoken()),
    });
    const { wrapper, router } = await open(s);
    await type(wrapper, '#name', '  Backup share link  ');
    await type(wrapper, '#notes', 'In the old wiki.');
    await type(wrapper, '#redirect', 'https://www.example.com/');
    await type(wrapper, '#techniques', 't1078, T1003.001 T1078');
    await wrapper.get('#severity').setValue('critical');
    await submit(wrapper);
    expect(s.requests.find((r) => r.method === 'POST')?.body).toEqual({
      type: 'web_url',
      name: 'Backup share link',
      notes: 'In the old wiki.',
      enabled: true,
      techniques: ['T1078', 'T1003.001'],
      redirect_url: 'https://www.example.com/',
      severity: 'critical',
    });
    await arrive(router, 'honeytoken');
    expect(wrapper.get('[role=status]').text()).toContain('The honeytoken has been created.');
  });

  test('asks for a name that is more than spaces, before it asks the server', async () => {
    const s = server('admin', { 'POST /api/v1/honeytokens': () => json(201, honeytoken()) });
    const { wrapper } = await open(s);
    await type(wrapper, '#name', '   ');
    await submit(wrapper);
    expect(wrapper.get('#name-problem').text()).toBe('Enter a name.');
    expect(wrapper.get('#name').attributes('aria-describedby')).toBe('name-problem');
    expect(s.requests.filter((r) => r.method === 'POST')).toHaveLength(0);
  });

  test('leaves out the severity, so that the server uses the default of the type, and an empty redirect', async () => {
    const s = server('admin', { 'POST /api/v1/honeytokens': () => json(201, honeytoken()) });
    const { wrapper } = await open(s);
    await type(wrapper, '#name', 'Plain');
    await submit(wrapper);
    const body = s.requests.find((r) => r.method === 'POST')?.body as Record<string, unknown>;
    expect(body).not.toHaveProperty('severity');
    expect(body).not.toHaveProperty('redirect_url');
  });

  test('has a redirect only for a web URL', async () => {
    const { wrapper } = await open();
    expect(wrapper.find('#redirect').exists()).toBe(true);
    await wrapper.get('#type').setValue('dns');
    expect(wrapper.find('#redirect').exists()).toBe(false);
  });

  test('does not send a redirect that was typed and then hidden by another type', async () => {
    const s = server('admin', { 'POST /api/v1/honeytokens': () => json(201, other) });
    const { wrapper } = await open(s);
    await type(wrapper, '#redirect', 'https://www.example.com/');
    await wrapper.get('#type').setValue('web_image');
    await type(wrapper, '#name', 'Image');
    await submit(wrapper);
    expect(s.requests.find((r) => r.method === 'POST')?.body).not.toHaveProperty('redirect_url');
  });

  test('does not send technique identifiers that are none, and says which', async () => {
    const s = server();
    const { wrapper } = await open(s);
    await type(wrapper, '#name', 'x');
    await type(wrapper, '#techniques', 'T1078, banana');
    await submit(wrapper);
    expect(wrapper.text()).toContain('These techniques were not found: banana');
    expect(s.requests.filter((r) => r.method === 'POST')).toHaveLength(0);
  });

  test('explains that DNS honeytokens need a zone', async () => {
    const { wrapper } = await open(server('admin', { 'POST /api/v1/honeytokens': () => failure(422, 'dns_not_configured') }));
    await wrapper.get('#type').setValue('dns');
    await type(wrapper, '#name', 'DNS');
    await submit(wrapper);
    expect(wrapper.get('[role=alert]').text()).toContain('NYKTUS_DNS_ZONES');
  });

  test('keeps the form for a failure', async () => {
    const { wrapper } = await open(server('admin', { 'POST /api/v1/honeytokens': () => failure(400, 'invalid_request') }));
    await type(wrapper, '#name', 'Keep me');
    await submit(wrapper);
    expect(wrapper.get('[role=alert]').text()).toBe('The input is not valid.');
    expect((wrapper.get('#name').element as HTMLInputElement).value).toBe('Keep me');
  });
});

describe('creating a honeytoken into a scenario', () => {
  const created = () => json(201, honeytoken({ scenario_id: scenarioId }));
  const withScenarios = (extra: Record<string, () => Response> = {}) =>
    server('admin', {
      'GET /api/v1/scenarios': () => json(200, { scenarios: [scenario()] }),
      'POST /api/v1/honeytokens': created,
      'GET /api/v1/honeytokens/c0ffee00-1111-4222-8333-944444444444': () => json(200, honeytoken({ scenario_id: scenarioId })),
      ...extra,
    });
  const bodyOf = (s: ReturnType<typeof server>) => s.requests.find((r) => r.method === 'POST')?.body as Record<string, unknown>;

  test('sends the scenario that was chosen', async () => {
    const s = withScenarios();
    const { wrapper } = await boot(s, '/honeytokens/new');
    expect(wrapper.get<HTMLSelectElement>('#scenario').element.value).toBe('');
    await type(wrapper, '#name', 'Linked');
    await wrapper.get('#scenario').setValue(scenarioId);
    await submit(wrapper);
    expect(bodyOf(s)).toMatchObject({ name: 'Linked', scenario_id: scenarioId });
  });

  test('sends no scenario when none was chosen', async () => {
    const s = withScenarios();
    const { wrapper } = await boot(s, '/honeytokens/new');
    await type(wrapper, '#name', 'Alone');
    await submit(wrapper);
    expect(bodyOf(s)).not.toHaveProperty('scenario_id');
  });

  test('takes the scenario that a link names', async () => {
    const s = withScenarios();
    const { wrapper } = await boot(s, `/honeytokens/new?scenario=${scenarioId}`);
    expect(wrapper.get<HTMLSelectElement>('#scenario').element.value).toBe(scenarioId);
    await type(wrapper, '#name', 'From a scenario');
    await submit(wrapper);
    expect(bodyOf(s)).toMatchObject({ scenario_id: scenarioId });
  });

  test('drops a scenario of the link that the list does not hold', async () => {
    const s = withScenarios();
    const { wrapper } = await boot(s, '/honeytokens/new?scenario=00000000-0000-4000-8000-000000000000');
    expect(wrapper.get<HTMLSelectElement>('#scenario').element.value).toBe('');
    await type(wrapper, '#name', 'Unknown');
    await submit(wrapper);
    expect(bodyOf(s)).not.toHaveProperty('scenario_id');
  });

  test('offers no choice, and sends none, where there is no scenario yet', async () => {
    const s = server('admin', { 'POST /api/v1/honeytokens': () => json(201, honeytoken()) });
    const { wrapper } = await boot(s, `/honeytokens/new?scenario=${scenarioId}`);
    expect(wrapper.find('#scenario').exists()).toBe(false);
    await type(wrapper, '#name', 'No scenarios');
    await submit(wrapper);
    expect(bodyOf(s)).not.toHaveProperty('scenario_id');
  });

  test('says so when the scenarios cannot be listed, and sends none', async () => {
    const s = withScenarios({ 'GET /api/v1/scenarios': () => failure(503, 'unavailable') });
    const { wrapper } = await boot(s, `/honeytokens/new?scenario=${scenarioId}`);
    expect(wrapper.find('#scenario').exists()).toBe(false);
    expect(wrapper.find('[role=alert]').exists()).toBe(true);
    await type(wrapper, '#name', 'No list');
    await submit(wrapper);
    expect(bodyOf(s)).not.toHaveProperty('scenario_id');
  });

  test('says so when the scenario is gone, and creates nothing', async () => {
    const s = withScenarios({ 'POST /api/v1/honeytokens': () => failure(422, 'scenario_not_found') });
    const { wrapper } = await boot(s, '/honeytokens/new');
    await type(wrapper, '#name', 'Too late');
    await wrapper.get('#scenario').setValue(scenarioId);
    await submit(wrapper);
    expect(wrapper.get('[role=alert]').text()).toBe('The request cannot be carried out.');
    expect(wrapper.find('#name').exists()).toBe(true);
  });

  test('is not offered when a honeytoken is changed', async () => {
    const { wrapper } = await boot(withScenarios({ 'GET /api/v1/honeytokens/c0ffee00-1111-4222-8333-944444444444': () => json(200, honeytoken()) }), '/honeytokens/c0ffee00-1111-4222-8333-944444444444');
    expect(wrapper.find('#scenario').exists()).toBe(false);
  });
});

describe('a honeytoken', () => {
  const path = '/honeytokens/c0ffee00-1111-4222-8333-944444444444';
  const one = (h = honeytoken(), extra: Record<string, () => Response> = {}) =>
    server('admin', { 'GET /api/v1/honeytokens/c0ffee00-1111-4222-8333-944444444444': () => json(200, h), ...extra });

  test('shows the URL to place, with a QR code of it', async () => {
    const { wrapper } = await boot(one(), path);
    expect(wrapper.get('h1').text()).toBe('Backup share link');
    expect(wrapper.get('.value').text()).toBe('https://t.example.net/abcdefghijklmnopqrstuvwxyz');
    const qr = wrapper.get('svg[role=img]');
    expect(qr.attributes('aria-label')).toBe('QR code of the URL of the honeytoken');
    expect(qr.get('path').attributes('d')).toMatch(/^M\d+ \d+h\d+v1h-\d+z/);
  });

  // The page of a resource loads it once, so another resource at the same page must be another page.
  test('shows the other honeytoken when the address changes to it, and acts on that one', async () => {
    const otherId = 'c0ffee00-9999-4222-8333-944444444444';
    const s = one(honeytoken(), { [`GET /api/v1/honeytokens/${otherId}`]: () => json(200, honeytoken({ id: otherId, name: 'The other one' })) });
    const { wrapper, router } = await boot(s, path);
    expect(wrapper.get('h1').text()).toBe('Backup share link');
    await router.push(`/honeytokens/${otherId}`);
    await flushPromises();
    await vi.waitFor(() => expect(wrapper.get('h1').text()).toBe('The other one'));
    expect(s.requests.some((r) => r.url === `/api/v1/honeytokens/${otherId}`)).toBe(true);
  });

  test('has no QR code for an image', async () => {
    const { wrapper } = await boot(one(honeytoken({ type: 'web_image', trigger_url: 'https://t.example.net/abcdefghijklmnopqrstuvwxyz.gif' })), path);
    expect(wrapper.find('main svg').exists()).toBe(false);
    expect(wrapper.get('.value').text()).toContain('.gif');
  });

  test('shows the names of a DNS honeytoken', async () => {
    const { wrapper } = await boot(one(other), path);
    expect(wrapper.findAll('.names .value').map((n) => n.text())).toEqual(other.trigger_names);
    expect(wrapper.find('main svg').exists()).toBe(false);
  });

  test('shows the notes and the times, and a name that is markup as text', async () => {
    const { wrapper } = await boot(one(honeytoken({ name: '<b>bold</b>', notes: '<img src=x onerror=alert(1)>' })), path);
    expect(wrapper.find('b').exists()).toBe(false);
    expect(wrapper.find('img[src=x]').exists()).toBe(false);
    expect(wrapper.get('h1').text()).toBe('<b>bold</b>');
    expect(wrapper.get('.notes').text()).toBe('<img src=x onerror=alert(1)>');
    expect(wrapper.get('time').attributes('title')).toBe('2026-10-20T08:30:00Z (UTC)');
  });

  test('says when it does not exist', async () => {
    const { wrapper } = await boot(one(honeytoken(), { 'GET /api/v1/honeytokens/c0ffee00-1111-4222-8333-944444444444': () => failure(404, 'not_found') }), path);
    expect(wrapper.get('[role=status]').text()).toBe('Nothing found here.');
    expect(wrapper.find('h1').exists()).toBe(false);
  });

  test('is only read by a viewer', async () => {
    const s = fakeServer({
      'GET /api/v1/session': () => json(200, sessionBody('viewer')),
      'GET /api/v1/honeytokens/c0ffee00-1111-4222-8333-944444444444': () => json(200, honeytoken()),
    });
    const { wrapper } = await boot(s, path);
    expect(wrapper.get('h1').text()).toBe('Backup share link');
    expect(wrapper.find('form').exists()).toBe(false);
    expect(wrapper.findAll('button').map((b) => b.text())).not.toContain('Delete');
  });

  describe('changed by someone who may', () => {
    let s: ReturnType<typeof one>;
    beforeEach(() => {
      s = one(honeytoken(), {
        'PATCH /api/v1/honeytokens/c0ffee00-1111-4222-8333-944444444444': () => json(200, honeytoken({ name: 'Renamed', updated_at: '2026-10-22T10:00:00Z' })),
      });
    });

    test('sends only what changed, and shows the answer', async () => {
      const { wrapper } = await boot(s, path);
      await type(wrapper, '#name', 'Renamed');
      await submit(wrapper);
      expect(s.requests.find((r) => r.method === 'PATCH')?.body).toEqual({ name: 'Renamed' });
      expect(wrapper.get('h1').text()).toBe('Renamed');
      expect(wrapper.text()).toContain('Saved.');
    });

    test('sends the state, the redirect and the techniques when they change, and null to remove a redirect', async () => {
      const withRedirect = one(honeytoken({ redirect_url: 'https://www.example.com/' }), {
        'PATCH /api/v1/honeytokens/c0ffee00-1111-4222-8333-944444444444': () => json(200, honeytoken()),
      });
      const { wrapper } = await boot(withRedirect, path);
      await wrapper.get('#enabled').setValue(false);
      await type(wrapper, '#redirect', '');
      await type(wrapper, '#techniques', 'T1078, T1003');
      await wrapper.get('#severity').setValue('low');
      await submit(wrapper);
      expect(withRedirect.requests.find((r) => r.method === 'PATCH')?.body).toEqual({
        enabled: false,
        redirect_url: null,
        techniques: ['T1078', 'T1003'],
        severity: 'low',
      });
    });

    test('sends nothing when nothing changed', async () => {
      const { wrapper } = await boot(s, path);
      await submit(wrapper);
      expect(s.requests.filter((r) => r.method === 'PATCH')).toHaveLength(0);
      expect(wrapper.text()).toContain('Saved.');
    });

    test('cannot change the type or the URL', async () => {
      const { wrapper } = await boot(s, path);
      expect(wrapper.get('#type').attributes('disabled')).toBeDefined();
      expect(wrapper.text()).toContain('The type cannot be changed.');
    });

    test('says why a change failed, and keeps what was typed', async () => {
      s.on('PATCH /api/v1/honeytokens/c0ffee00-1111-4222-8333-944444444444', () => failure(400, 'invalid_request'));
      const { wrapper } = await boot(s, path);
      await type(wrapper, '#name', 'Typed');
      await submit(wrapper);
      expect(wrapper.get('[role=alert]').text()).toBe('The input is not valid.');
      expect((wrapper.get('#name').element as HTMLInputElement).value).toBe('Typed');
    });
  });

  describe('deleted', () => {
    const del = 'DELETE /api/v1/honeytokens/c0ffee00-1111-4222-8333-944444444444';

    async function ask() {
      const s = one(honeytoken(), { [del]: noContent });
      const app = await boot(s, path);
      const button = app.wrapper.findAll('button').find((b) => b.text() === 'Delete')!;
      await button.trigger('click');
      await flushPromises();
      return { ...app, s };
    }

    test('only after the user confirms', async () => {
      const { wrapper, router, s } = await ask();
      expect(wrapper.get('dialog').attributes('open')).toBeDefined();
      expect(wrapper.get('dialog h2').text()).toBe('Delete this honeytoken?');
      expect(s.requests.filter((r) => r.method === 'DELETE')).toHaveLength(0);
      await wrapper.get('dialog .danger').trigger('click');
      await flushPromises();
      expect(s.requests.filter((r) => r.method === 'DELETE')).toHaveLength(1);
      await arrive(router, 'honeytokens');
    });

    test('not when the user cancels', async () => {
      const { wrapper, router, s } = await ask();
      await wrapper.get('dialog .button-ghost').trigger('click');
      await flushPromises();
      expect(wrapper.get('dialog').attributes('open')).toBeUndefined();
      expect(s.requests.filter((r) => r.method === 'DELETE')).toHaveLength(0);
      expect(router.currentRoute.value.name).toBe('honeytoken');
    });

    test('and says so when the server refuses', async () => {
      const { wrapper, s } = await ask();
      s.on(del, () => failure(503, 'unavailable'));
      await wrapper.get('dialog .danger').trigger('click');
      await flushPromises();
      expect(wrapper.get('[role=alert]').text()).toBe('The server is busy. Try again in a moment.');
      expect(wrapper.get('dialog').attributes('open')).toBeUndefined();
    });
  });
});
