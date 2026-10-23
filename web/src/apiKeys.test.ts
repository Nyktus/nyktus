// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises } from '@vue/test-utils';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { keyScopes } from './api/generated';
import { arrive, boot } from './testing/boot';
import { apiKey, createdKey, failure, fakeServer, json, keyId, keySecret, noContent, sessionBody, type Handler } from './testing/fakeServer';

beforeEach(() => {
  // Only the clock is replaced: the date that the form offers and the expiry of a key follow it.
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(new Date('2026-10-23T17:30:00Z'));
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  document.body.innerHTML = '';
  history.replaceState(null, '', '/');
});

type Role = 'admin' | 'user' | 'viewer';
type Wrapper = Awaited<ReturnType<typeof boot>>['wrapper'];

const typed = 'test-password-not-real';

function server(role: Role = 'admin', extra: Record<string, Handler> = {}, method: 'password' | 'oidc' = 'password') {
  return fakeServer({
    'GET /api/v1/session': () => json(200, sessionBody(role, 'Ada Admin', method)),
    'GET /api/v1/api-keys': () => json(200, { api_keys: [apiKey()] }),
    ...extra,
  });
}

const requestsOf = (s: ReturnType<typeof server>, method: string) => s.requests.filter((r) => r.method === method);
// A button of the page, not one of its dialogs, which are always in the page and may carry the same text.
const button = (wrapper: Wrapper, label: string) => wrapper.findAll('button').find((b) => b.text() === label && b.element.closest('dialog') === null);
const dialog = (wrapper: Wrapper) => wrapper.get('dialog[open]');
const box = (wrapper: Wrapper, scope: string) => wrapper.get(`#scope-${keyScopes.indexOf(scope as (typeof keyScopes)[number])}`);
const checked = (wrapper: Wrapper): string[] => keyScopes.filter((scope) => (box(wrapper, scope).element as HTMLInputElement).checked);

describe('the list of API keys', () => {
  test('shows each key with its scopes, creation, expiry and last use', async () => {
    const used = apiKey({ id: 'ba5e0000-2222-4222-8333-944444444444', name: 'Tickets', scopes: ['incidents:read', 'incidents:write'], last_used_at: '2026-10-22T10:15:00Z' });
    const s = server('admin', { 'GET /api/v1/api-keys': () => json(200, { api_keys: [apiKey(), used] }) });
    const { wrapper } = await boot(s, '/api-keys');
    const rows = wrapper.findAll('tbody tr');
    expect(rows).toHaveLength(2);
    expect(rows[0]?.text()).toContain('SIEM export');
    expect(rows[0]?.text()).toContain('audit:read');
    expect(rows[0]?.text()).toContain('Never');
    expect(rows[1]?.text()).toContain('incidents:read, incidents:write');
    expect(rows[1]?.get('td:nth-child(5) time').attributes('datetime')).toBe('2026-10-22T10:15:00Z');
  });

  test('marks a key that has expired', async () => {
    const old = apiKey({ id: 'ba5e0000-3333-4222-8333-944444444444', expires_at: '2026-10-01T00:00:00Z' });
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/api-keys': () => json(200, { api_keys: [apiKey(), old] }) }), '/api-keys');
    const rows = wrapper.findAll('tbody tr');
    expect(rows[0]?.text()).not.toContain('Expired');
    expect(rows[1]?.text()).toContain('Expired');
  });

  test('says so when there are none, and when the list cannot be loaded', async () => {
    const none = await boot(server('admin', { 'GET /api/v1/api-keys': () => json(200, { api_keys: [] }) }), '/api-keys');
    expect(none.wrapper.text()).toContain('There are no API keys.');
    document.body.innerHTML = '';
    const failed = await boot(server('admin', { 'GET /api/v1/api-keys': () => failure(500, 'internal_error') }), '/api-keys');
    expect(failed.wrapper.get('[role=alert]').text()).toContain('The API keys could not be loaded.');
  });

  test('shows a name that is markup as text', async () => {
    const s = server('admin', { 'GET /api/v1/api-keys': () => json(200, { api_keys: [apiKey({ name: '<img src=x onerror=alert(1)>' })] }) });
    const { wrapper } = await boot(s, '/api-keys');
    expect(wrapper.find('img[src=x]').exists()).toBe(false);
    expect(wrapper.get('tbody td').text()).toBe('<img src=x onerror=alert(1)>');
  });

  test('offers a new key to an administrator, and is in the navigation', async () => {
    const { wrapper } = await boot(server(), '/api-keys');
    expect(wrapper.get('.page-head a').attributes('href')).toBe('/api-keys/new');
    expect(wrapper.findAll('nav a').map((a) => a.text())).toContain('API keys');
  });

  test.each(['user', 'viewer'] as const)('is hidden from the role %s, and its pages do not open', async (role) => {
    const { wrapper, router } = await boot(server(role), '/');
    expect(wrapper.findAll('nav a').map((a) => a.text())).not.toContain('API keys');
    for (const target of ['/api-keys', '/api-keys/new']) {
      await router.push(target);
      await arrive(router, 'forbidden');
    }
  });

  describe('revoked', () => {
    test('only after the user confirms, and the row goes', async () => {
      const s = server('admin', { [`DELETE /api/v1/api-keys/${keyId}`]: noContent });
      const { wrapper } = await boot(s, '/api-keys');
      await button(wrapper, 'Revoke')!.trigger('click');
      await flushPromises();
      expect(dialog(wrapper).get('h2').text()).toBe('Revoke this API key?');
      expect(dialog(wrapper).find('input[type=password]').exists()).toBe(false);
      expect(requestsOf(s, 'DELETE')).toHaveLength(0);
      await dialog(wrapper).get('.danger').trigger('click');
      await flushPromises();
      expect(requestsOf(s, 'DELETE')).toHaveLength(1);
      expect(wrapper.findAll('tbody tr')).toHaveLength(0);
      expect(wrapper.find('dialog[open]').exists()).toBe(false);
    });

    test('revokes the key that was chosen, among several', async () => {
      const other = apiKey({ id: 'ba5e0000-2222-4222-8333-944444444444', name: 'Tickets' });
      const s = server('admin', {
        'GET /api/v1/api-keys': () => json(200, { api_keys: [apiKey(), other] }),
        [`DELETE /api/v1/api-keys/${other.id}`]: noContent,
      });
      const { wrapper } = await boot(s, '/api-keys');
      await wrapper.findAll('tbody tr')[1]!.get('button').trigger('click');
      await flushPromises();
      await dialog(wrapper).get('.danger').trigger('click');
      await flushPromises();
      expect(requestsOf(s, 'DELETE').map((r) => r.url)).toEqual([`/api/v1/api-keys/${other.id}`]);
      expect(wrapper.findAll('tbody tr')).toHaveLength(1);
      expect(wrapper.get('tbody td').text()).toBe('SIEM export');
    });

    test('does nothing when the user cancels', async () => {
      const s = server();
      const { wrapper } = await boot(s, '/api-keys');
      await button(wrapper, 'Revoke')!.trigger('click');
      await flushPromises();
      await dialog(wrapper).get('.button-ghost').trigger('click');
      await flushPromises();
      expect(requestsOf(s, 'DELETE')).toHaveLength(0);
      expect(wrapper.findAll('tbody tr')).toHaveLength(1);
    });

    test('takes the row away when the key is gone already, which is what the user wanted', async () => {
      const s = server('admin', { [`DELETE /api/v1/api-keys/${keyId}`]: () => failure(404, 'not_found') });
      const { wrapper } = await boot(s, '/api-keys');
      await button(wrapper, 'Revoke')!.trigger('click');
      await flushPromises();
      await dialog(wrapper).get('.danger').trigger('click');
      await flushPromises();
      expect(wrapper.find('[role=alert]').exists()).toBe(false);
      expect(wrapper.findAll('tbody tr')).toHaveLength(0);
    });

    test('keeps the row and says so when the server refuses', async () => {
      const s = server('admin', { [`DELETE /api/v1/api-keys/${keyId}`]: () => failure(503, 'unavailable') });
      const { wrapper } = await boot(s, '/api-keys');
      await button(wrapper, 'Revoke')!.trigger('click');
      await flushPromises();
      await dialog(wrapper).get('.danger').trigger('click');
      await flushPromises();
      expect(wrapper.get('[role=alert]').text()).toBe('The server is busy. Try again in a moment.');
      expect(wrapper.findAll('tbody tr')).toHaveLength(1);
    });
  });
});

describe('a new API key', () => {
  const create = '/api-keys/new';

  function creating(extra: Record<string, Handler> = {}, method: 'password' | 'oidc' = 'password') {
    return server('admin', { 'POST /api/v1/api-keys': () => json(201, createdKey(), { 'Cache-Control': 'no-store' }), ...extra }, method);
  }

  async function fill(wrapper: Wrapper, scopes: string[] = ['audit:read']): Promise<void> {
    await wrapper.get('#key-name').setValue(' SIEM export ');
    await wrapper.get('#key-expires').setValue('2027-01-31');
    for (const scope of scopes) {
      await box(wrapper, scope).setValue(true);
    }
  }

  const ask = async (wrapper: Wrapper) => {
    await wrapper.get('form.stack').trigger('submit');
    await flushPromises();
  };

  async function make(s = creating(), scopes?: string[]) {
    const app = await boot(s, create);
    await fill(app.wrapper, scopes);
    await ask(app.wrapper);
    await dialog(app.wrapper).get('input[type=password]').setValue(typed);
    await dialog(app.wrapper).get('.button-primary').trigger('click');
    await flushPromises();
    return { ...app, s };
  }

  test('keeps the name from the memory of the browser, which would offer it to the next form', async () => {
    const { wrapper } = await boot(creating(), create);
    expect(wrapper.get('#key-name').attributes('autocomplete')).toBe('off');
  });

  describe('the scopes', () => {
    test('are the ones of the server, in its order', async () => {
      const { wrapper } = await boot(creating(), create);
      const labels = wrapper.findAll('fieldset .field code').map((c) => c.text());
      expect(labels).toEqual([...keyScopes]);
      expect(wrapper.findAll('fieldset input[type=checkbox]')).toHaveLength(keyScopes.length);
      expect(checked(wrapper)).toEqual([]);
    });

    test('never offer what would let a leaked key take over accounts, keys or alerts', async () => {
      const { wrapper } = await boot(creating(), create);
      const text = wrapper.get('fieldset').text();
      for (const never of ['users:', 'api_keys:', 'alert_channels:']) {
        expect(text).not.toContain(never);
      }
    });

    test('select what a scope requires, also through another scope', async () => {
      const { wrapper } = await boot(creating(), create);
      await box(wrapper, 'scenarios:write').setValue(true);
      expect(checked(wrapper)).toEqual(['honeytokens:read', 'scenarios:read', 'scenarios:write']);
    });

    test('cannot be taken away while a selected scope needs them, and say which', async () => {
      const { wrapper } = await boot(creating(), create);
      await box(wrapper, 'incidents:write').setValue(true);
      expect(box(wrapper, 'incidents:read').attributes('disabled')).toBeDefined();
      expect(box(wrapper, 'incidents:write').attributes('disabled')).toBeUndefined();
      expect(wrapper.text()).toContain('Needed by incidents:write.');
      await box(wrapper, 'incidents:write').setValue(false);
      expect(box(wrapper, 'incidents:read').attributes('disabled')).toBeUndefined();
      await box(wrapper, 'incidents:read').setValue(false);
      expect(checked(wrapper)).toEqual([]);
    });

    test('say what a scope needs before it is chosen', async () => {
      const { wrapper } = await boot(creating(), create);
      expect(wrapper.text()).toContain('Needs honeytokens:read, scenarios:read.');
    });
  });

  test('offers the days from tomorrow to just under three years, in UTC', async () => {
    const { wrapper } = await boot(creating(), create);
    expect(wrapper.get('#key-expires').attributes('min')).toBe('2026-10-24');
    expect(wrapper.get('#key-expires').attributes('max')).toBe('2029-10-22');
  });

  test.each([
    ['no name', async (w: Wrapper) => w.get('#key-name').setValue('  '), 'Give the key a name.'],
    ['no scope', async (w: Wrapper) => box(w, 'audit:read').setValue(false), 'Choose at least one scope.'],
    ['no day', async (w: Wrapper) => w.get('#key-expires').setValue(''), 'Choose a day from 2026-10-24 to 2029-10-22.'],
    ['today', async (w: Wrapper) => w.get('#key-expires').setValue('2026-10-23'), 'Choose a day from 2026-10-24 to 2029-10-22.'],
    ['a day beyond three years', async (w: Wrapper) => w.get('#key-expires').setValue('2029-10-23'), 'Choose a day from 2026-10-24 to 2029-10-22.'],
  ])('does not ask for a key with %s', async (_, change, text) => {
    const s = creating();
    const { wrapper } = await boot(s, create);
    await fill(wrapper);
    await change(wrapper);
    await ask(wrapper);
    expect(wrapper.find('dialog[open]').exists()).toBe(false);
    expect(wrapper.get('form.stack [role=alert]').text()).toBe(text);
    expect(requestsOf(s, 'POST')).toHaveLength(0);
  });

  test('takes the message away once the input is right', async () => {
    const { wrapper } = await boot(creating(), create);
    await fill(wrapper);
    await wrapper.get('#key-name').setValue('');
    await ask(wrapper);
    expect(wrapper.find('form.stack [role=alert]').exists()).toBe(true);
    await wrapper.get('#key-name').setValue('SIEM');
    await ask(wrapper);
    expect(wrapper.find('form.stack [role=alert]').exists()).toBe(false);
    expect(dialog(wrapper).get('h2').text()).toBe('Create this API key?');
  });

  test('sends nothing when the user cancels the question', async () => {
    const s = creating();
    const { wrapper } = await boot(s, create);
    await fill(wrapper);
    await ask(wrapper);
    await dialog(wrapper).get('.button-ghost').trigger('click');
    await flushPromises();
    expect(wrapper.find('dialog[open]').exists()).toBe(false);
    expect(requestsOf(s, 'POST')).toHaveLength(0);
  });

  test('asks for the password first, and sends nothing before it', async () => {
    const s = creating();
    const { wrapper } = await boot(s, create);
    await fill(wrapper);
    await ask(wrapper);
    expect(dialog(wrapper).get('h2').text()).toBe('Create this API key?');
    expect(requestsOf(s, 'POST')).toHaveLength(0);
  });

  test('sends the name, the scopes and the start of the day of expiry, with the password', async () => {
    const { s } = await make(creating(), ['honeytokens:write']);
    expect(requestsOf(s, 'POST').map((r) => r.body)).toEqual([
      { name: 'SIEM export', scopes: ['honeytokens:read', 'honeytokens:write'], expires_at: '2027-01-31T00:00:00Z', password: typed },
    ]);
  });

  describe('the key', () => {
    test('is shown once, with the warning', async () => {
      const { wrapper } = await make();
      expect(wrapper.get('[role=region]').text()).toContain(keySecret);
      expect(wrapper.get('[role=region]').text()).toContain('This is the only time the key is shown.');
      expect(wrapper.find('form.stack').exists()).toBe(false);
    });

    test('is what the button copies', async () => {
      const writeText = vi.fn().mockResolvedValue(undefined);
      vi.stubGlobal('navigator', { ...globalThis.navigator, clipboard: { writeText } });
      const { wrapper } = await make();
      await wrapper.get('[role=region] button.small').trigger('click');
      expect(writeText).toHaveBeenCalledExactlyOnceWith(keySecret);
    });

    test('is gone once the user says that they copied it', async () => {
      const { wrapper } = await make();
      await wrapper.get('[role=region] button.button-primary').trigger('click');
      expect(wrapper.html()).not.toContain(keySecret);
      expect(wrapper.find('[role=region]').exists()).toBe(false);
    });

    test('is gone when the user leaves, and the list that they go to does not have it', async () => {
      const { wrapper, router } = await make();
      await wrapper.get('a.button-primary').trigger('click');
      await arrive(router, 'api-keys');
      expect(wrapper.html()).not.toContain(keySecret);
      expect(wrapper.text()).toContain('SIEM export');
    });

    test('is kept nowhere: not in the address, the history, the storage, a request or the password field', async () => {
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
      expect(everything).not.toContain(keySecret);
      expect(everything).not.toContain(typed);
      expect(wrapper.html()).not.toContain(typed);
      for (const input of document.querySelectorAll('input')) {
        expect((input as HTMLInputElement).value).not.toBe(typed);
      }
    });
  });

  describe('when the password is not right', () => {
    test('says so in the dialog, shows no key, and empties the field', async () => {
      const { wrapper } = await make(creating({ 'POST /api/v1/api-keys': () => failure(403, 'wrong_password') }));
      expect(dialog(wrapper).get('[role=alert]').text()).toBe('The password is wrong.');
      expect((dialog(wrapper).get('input[type=password]').element as HTMLInputElement).value).toBe('');
      expect(wrapper.find('[role=region]').exists()).toBe(false);
    });
  });

  describe('when the server refuses', () => {
    test.each([
      [409, 'too_many_api_keys', 'reached the limit'],
      [400, 'invalid_request', 'The input is not valid.'],
    ])('says what is wrong for %i %s, closes the dialog and keeps the form', async (status, code, text) => {
      const { wrapper } = await make(creating({ 'POST /api/v1/api-keys': () => failure(status, code) }));
      expect(wrapper.find('dialog[open]').exists()).toBe(false);
      expect(wrapper.get('section > [role=alert]').text()).toContain(text);
      expect((wrapper.get('#key-name').element as HTMLInputElement).value).toBe(' SIEM export ');
      expect(wrapper.find('[role=region]').exists()).toBe(false);
    });
  });

  describe('for an account of the identity provider', () => {
    test('asks for no password and sends none', async () => {
      const s = creating({}, 'oidc');
      const { wrapper } = await boot(s, create);
      await fill(wrapper);
      await ask(wrapper);
      expect(dialog(wrapper).find('input[type=password]').exists()).toBe(false);
      await dialog(wrapper).get('.button-primary').trigger('click');
      await flushPromises();
      expect(requestsOf(s, 'POST')[0]?.body).not.toHaveProperty('password');
      expect(wrapper.get('[role=region]').text()).toContain(keySecret);
    });

    test('is sent to sign in again, and back to this page', async () => {
      const assign = vi.spyOn(globalThis.location, 'assign').mockImplementation(() => {});
      const s = creating({ 'POST /api/v1/api-keys': () => failure(403, 'reauthentication_required') }, 'oidc');
      const { wrapper } = await boot(s, create);
      await fill(wrapper);
      await ask(wrapper);
      await dialog(wrapper).get('.button-primary').trigger('click');
      await flushPromises();
      await dialog(wrapper).get('.button-primary').trigger('click');
      expect(assign).toHaveBeenCalledExactlyOnceWith('/api/v1/oidc/reauthenticate?return_to=%2Fapi-keys%2Fnew');
    });
  });
});

describe('the pages in German', () => {
  test('speak German and keep the values as they are', async () => {
    const { wrapper, i18n } = await boot(server(), '/api-keys');
    i18n.setLocale('de');
    await flushPromises();
    expect(wrapper.text()).toContain('Widerrufen');
    expect(wrapper.text()).toContain('SIEM export');
  });
});
