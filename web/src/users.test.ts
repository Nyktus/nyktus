// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises } from '@vue/test-utils';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { arrive, boot } from './testing/boot';
import { failure, fakeServer, json, noContent, ownRecord, sessionBody, userId, userRecord, type Handler } from './testing/fakeServer';

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = '';
  history.replaceState(null, '', '/');
});

type Role = 'admin' | 'user' | 'viewer';
type Wrapper = Awaited<ReturnType<typeof boot>>['wrapper'];

const detail = `/api/v1/users/${userId}`;
const path = `/users/${userId}`;
// Plainly made up, so that a scan for secrets does not take it for a real token.
const token = `test-token-${'x'.repeat(33)}`;
const link = `https://nyktus.example.com/activate#token=${token}`;
const typed = 'test-password-not-real';

function server(role: Role = 'admin', extra: Record<string, Handler> = {}) {
  return fakeServer({
    'GET /api/v1/session': () => json(200, sessionBody(role)),
    'GET /api/v1/users': () => json(200, { users: [ownRecord(), userRecord()] }),
    [`GET ${detail}`]: () => json(200, userRecord()),
    ...extra,
  });
}

const requestsOf = (s: ReturnType<typeof server>, method: string) => s.requests.filter((r) => r.method === method);
// A button of the page, not one of its dialogs, which are always in the page and may carry the same text.
const button = (wrapper: Wrapper, label: string) => wrapper.findAll('button').find((b) => b.text() === label && b.element.closest('dialog') === null);
const dialog = (wrapper: Wrapper) => wrapper.get('dialog[open]');

describe('the list of accounts', () => {
  test('shows each account with its role, status and sign-in', async () => {
    const pending = userRecord({ id: 'a5e70000-2222-4222-8333-944444444444', display_name: 'New Hire', email: 'new@example.com', status: 'pending', role: 'viewer' });
    const sso = userRecord({ id: 'a5e70000-3333-4222-8333-944444444444', display_name: 'Sam SSO', sign_in_method: 'oidc', totp_enabled: false });
    const secured = userRecord({ id: 'a5e70000-4444-4222-8333-944444444444', display_name: 'Tom TOTP', totp_enabled: true, status: 'deactivated' });
    const s = server('admin', { 'GET /api/v1/users': () => json(200, { users: [ownRecord(), pending, sso, secured] }) });
    const { wrapper } = await boot(s, '/users');
    const rows = wrapper.findAll('tbody tr');
    expect(rows).toHaveLength(4);
    expect(rows[0]?.text()).toContain('Ada Admin');
    expect(rows[0]?.text()).toContain('Administrator');
    expect(rows[1]?.text()).toContain('Pending');
    expect(rows[1]?.text()).toContain('Viewer');
    expect(rows[2]?.text()).toContain('Identity provider');
    expect(rows[3]?.text()).toContain('Deactivated');
    expect(rows[3]?.get('.badge').classes()).toContain('badge-muted');
    expect(rows[0]?.get('.badge').classes()).not.toContain('badge-muted');
    expect(rows[3]?.text()).toContain('Password, second factor on');
    expect(rows[1]?.get('a').attributes('href')).toBe('/users/a5e70000-2222-4222-8333-944444444444');
  });

  test('reads the next page with the cursor', async () => {
    const s = server('admin', {
      'GET /api/v1/users': (r) => (r.url.includes('cursor=more') ? json(200, { users: [userRecord()] }) : json(200, { users: [ownRecord()], next_cursor: 'more' })),
    });
    const { wrapper } = await boot(s, '/users');
    await button(wrapper, 'Load more')!.trigger('click');
    await flushPromises();
    expect(wrapper.findAll('tbody tr')).toHaveLength(2);
    expect(s.requests.at(-1)?.url).toBe('/api/v1/users?limit=50&cursor=more');
  });

  test('says so when the list cannot be loaded', async () => {
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/users': () => failure(500, 'internal_error') }), '/users');
    expect(wrapper.get('[role=alert]').text()).toContain('The accounts could not be loaded.');
  });

  test('shows a name that is markup as text', async () => {
    const s = server('admin', { 'GET /api/v1/users': () => json(200, { users: [userRecord({ display_name: '<img src=x onerror=alert(1)>' })] }) });
    const { wrapper } = await boot(s, '/users');
    expect(wrapper.find('img[src=x]').exists()).toBe(false);
    expect(wrapper.get('tbody a').text()).toBe('<img src=x onerror=alert(1)>');
  });

  test('offers a new account to an administrator, and is in the navigation', async () => {
    const { wrapper } = await boot(server(), '/users');
    expect(wrapper.get('.page-head a.button').attributes('href')).toBe('/users/new');
    expect(wrapper.findAll('nav a').map((a) => a.text())).toContain('Accounts');
  });

  test.each(['user', 'viewer'] as const)('is hidden from the role %s, and its pages do not open', async (role) => {
    const { wrapper, router } = await boot(server(role), '/');
    expect(wrapper.findAll('nav a').map((a) => a.text())).not.toContain('Accounts');
    for (const target of ['/users', '/users/new', path]) {
      await router.push(target);
      await arrive(router, 'forbidden');
    }
  });
});

describe('a new account', () => {
  const created = userRecord({ status: 'pending' });
  const answer = () => json(201, { user: created, activation: { url: link, expires_at: '2026-10-26T08:00:00Z' } }, { 'Cache-Control': 'no-store' });

  async function make(s = server('admin', { 'POST /api/v1/users': answer, [`GET ${detail}`]: () => json(200, created) })) {
    const app = await boot(s, '/users/new');
    await app.wrapper.get('#email').setValue(' jane@example.com ');
    await app.wrapper.get('#display-name').setValue(' Jane Doe ');
    await app.wrapper.get('#role').setValue('admin');
    await app.wrapper.get('form').trigger('submit');
    await flushPromises();
    return { ...app, s };
  }

  test('sends what was entered, trimmed', async () => {
    const { s } = await make();
    expect(requestsOf(s, 'POST').map((r) => r.body)).toEqual([{ email: 'jane@example.com', display_name: 'Jane Doe', role: 'admin' }]);
  });

  test('starts as a viewer, who can change nothing, and says what each role does', async () => {
    const { wrapper } = await boot(server(), '/users/new');
    expect((wrapper.get('#role').element as HTMLSelectElement).value).toBe('viewer');
    expect(wrapper.get('#role-hint').text()).toContain('changes nothing');
    await wrapper.get('#role').setValue('admin');
    expect(wrapper.get('#role-hint').text()).toContain('Manages the installation');
  });

  test('shows the activation link once, with when it expires', async () => {
    const { wrapper } = await make();
    expect(wrapper.get('[role=region]').text()).toContain(link);
    expect(wrapper.get('[role=region]').text()).toContain('This is the only time the link is shown.');
    expect(wrapper.get('[role=region] time').attributes('datetime')).toBe('2026-10-26T08:00:00Z');
  });

  test('asks for a name that is more than spaces, before it asks the server', async () => {
    const s = server('admin', { 'POST /api/v1/users': answer });
    const { wrapper } = await boot(s, '/users/new');
    await wrapper.get('#email').setValue('jane@example.com');
    await wrapper.get('#display-name').setValue('   ');
    await wrapper.get('form').trigger('submit');
    await flushPromises();
    expect(wrapper.get('[role=alert]').text()).toBe('Enter a name.');
    expect(requestsOf(s, 'POST')).toHaveLength(0);
  });

  test('is gone once the user says that they passed it on', async () => {
    const { wrapper } = await make();
    await wrapper.get('[role=region] button.button-primary').trigger('click');
    expect(wrapper.html()).not.toContain(token);
    expect(wrapper.find('[role=region]').exists()).toBe(false);
  });

  test('is gone when the user leaves, and the page that they go to does not have it', async () => {
    const { wrapper, router } = await make();
    await wrapper.get('a.button-primary').trigger('click');
    await arrive(router, 'user');
    expect(wrapper.html()).not.toContain(token);
  });

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
    expect(everything).not.toContain(token);
    expect(wrapper.html()).toContain(token);
  });

  test.each([
    [409, 'email_taken', 'Another account uses this email address.'],
    [400, 'invalid_request', 'The input is not valid.'],
  ])('says what is wrong when the server answers %i %s, and shows no link', async (status, code, text) => {
    const { wrapper } = await make(server('admin', { 'POST /api/v1/users': () => failure(status, code) }));
    expect(wrapper.get('[role=alert]').text()).toBe(text);
    expect(wrapper.find('[role=region]').exists()).toBe(false);
    expect(wrapper.find('form').exists()).toBe(true);
  });
});

describe('an account', () => {
  test('shows its address, role, status and second factor', async () => {
    const { wrapper } = await boot(server('admin', { [`GET ${detail}`]: () => json(200, userRecord({ totp_enabled: true })) }), path);
    expect(wrapper.get('h1').text()).toBe('Jane Doe');
    expect(wrapper.get('dl').text()).toContain('jane@example.com');
    expect(wrapper.get('dl').text()).toContain('Second factor on');
    expect(wrapper.get('.badges').text()).toContain('Active');
  });

  test('says when it does not exist, and when it cannot be loaded', async () => {
    const gone = await boot(server('admin', { [`GET ${detail}`]: () => failure(404, 'not_found') }), path);
    expect(gone.wrapper.text()).toContain('This does not exist.');
    document.body.innerHTML = '';
    const failed = await boot(server('admin', { [`GET ${detail}`]: () => failure(500, 'internal_error') }), path);
    expect(failed.wrapper.get('[role=alert]').text()).toBe('Something went wrong on the server.');
  });

  test('shows a name that is markup as text', async () => {
    const { wrapper } = await boot(server('admin', { [`GET ${detail}`]: () => json(200, userRecord({ display_name: '<img src=x onerror=alert(1)>' })) }), path);
    expect(wrapper.find('img[src=x]').exists()).toBe(false);
    expect(wrapper.get('h1').text()).toBe('<img src=x onerror=alert(1)>');
  });

  describe('changed', () => {
    const save = async (wrapper: Wrapper) => {
      await wrapper.findAll('form')[0]!.trigger('submit');
      await flushPromises();
    };

    test('with only the display name, at once and without a question', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => json(200, userRecord({ display_name: 'Jane Roe' })) });
      const { wrapper } = await boot(s, path);
      await wrapper.get('#display-name').setValue(' Jane Roe ');
      await save(wrapper);
      expect(requestsOf(s, 'PATCH').map((r) => r.body)).toEqual([{ display_name: 'Jane Roe' }]);
      expect(wrapper.find('dialog[open]').exists()).toBe(false);
      expect(wrapper.get('h1').text()).toBe('Jane Roe');
      expect(wrapper.text()).toContain('Saved.');
    });

    test('takes the notice of a saved change away when the next one fails', async () => {
      let fail = false;
      const s = server('admin', { [`PATCH ${detail}`]: () => (fail ? failure(500, 'internal_error') : json(200, userRecord({ display_name: 'Jane Roe' }))) });
      const { wrapper } = await boot(s, path);
      await wrapper.get('#display-name').setValue('Jane Roe');
      await save(wrapper);
      expect(wrapper.text()).toContain('Saved.');
      fail = true;
      await wrapper.get('#display-name').setValue('Jane R.');
      await save(wrapper);
      expect(wrapper.text()).not.toContain('Saved.');
    });

    test('asks for a name that is more than spaces, and sends nothing', async () => {
      const s = server();
      const { wrapper } = await boot(s, path);
      await wrapper.get('#display-name').setValue('   ');
      await save(wrapper);
      expect(wrapper.get('[role=alert]').text()).toBe('Enter a name.');
      expect(requestsOf(s, 'PATCH')).toHaveLength(0);
    });

    test('sends nothing when only the spaces around the name differ', async () => {
      const s = server();
      const { wrapper } = await boot(s, path);
      await wrapper.get('#display-name').setValue('  Jane Doe  ');
      await save(wrapper);
      expect(requestsOf(s, 'PATCH')).toHaveLength(0);
    });

    test('shows what the server holds, not the change that it refused', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => failure(409, 'last_active_admin') });
      const { wrapper } = await boot(s, path);
      await wrapper.get('#role').setValue('viewer');
      await save(wrapper);
      await dialog(wrapper).get('.button-primary').trigger('click');
      await flushPromises();
      expect(wrapper.get('[role=alert]').text()).toContain('At least one active administrator');
      expect((wrapper.get('#role').element as HTMLSelectElement).value).toBe('user');
      expect(wrapper.get('.badges').text()).toContain('User');
    });

    test('sends nothing when nothing changed', async () => {
      const s = server();
      const { wrapper } = await boot(s, path);
      await save(wrapper);
      expect(requestsOf(s, 'PATCH')).toHaveLength(0);
      expect(wrapper.text()).toContain('Saved.');
    });

    test('with a new role only after the user has read that it ends the sessions', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => json(200, userRecord({ role: 'viewer' })) });
      const { wrapper } = await boot(s, path);
      await wrapper.get('#role').setValue('viewer');
      await save(wrapper);
      expect(dialog(wrapper).get('h2').text()).toBe('End the sessions of this account?');
      expect(requestsOf(s, 'PATCH')).toHaveLength(0);
      await dialog(wrapper).get('.button-primary').trigger('click');
      await flushPromises();
      expect(requestsOf(s, 'PATCH').map((r) => r.body)).toEqual([{ role: 'viewer' }]);
      expect(wrapper.get('.badges').text()).toContain('Viewer');
      expect(wrapper.find('dialog[open]').exists()).toBe(false);
    });

    test('with a new status, which is asked about as well, and sends the role as it was left out', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => json(200, userRecord({ status: 'deactivated' })) });
      const { wrapper } = await boot(s, path);
      await wrapper.get('#status').setValue('deactivated');
      await wrapper.get('#display-name').setValue('Jane D.');
      await save(wrapper);
      await dialog(wrapper).get('.button-primary').trigger('click');
      await flushPromises();
      expect(requestsOf(s, 'PATCH').map((r) => r.body)).toEqual([{ display_name: 'Jane D.', status: 'deactivated' }]);
      expect(wrapper.get('.badges').text()).toContain('Deactivated');
    });

    test('does nothing when the user cancels', async () => {
      const s = server();
      const { wrapper } = await boot(s, path);
      await wrapper.get('#role').setValue('viewer');
      await save(wrapper);
      await dialog(wrapper).get('.button-ghost').trigger('click');
      await flushPromises();
      expect(requestsOf(s, 'PATCH')).toHaveLength(0);
      expect(wrapper.find('dialog[open]').exists()).toBe(false);
    });

    test('keeps a pending account pending, and offers no status for it to take', async () => {
      const s = server('admin', { [`GET ${detail}`]: () => json(200, userRecord({ status: 'pending' })) });
      const { wrapper } = await boot(s, path);
      const pendingOption = wrapper.get('#status option[value=pending]');
      expect(pendingOption.attributes('disabled')).toBeDefined();
      await wrapper.get('#display-name').setValue('Jane D.');
      await save(wrapper);
      expect(requestsOf(s, 'PATCH').map((r) => r.body)).toEqual([{ display_name: 'Jane D.' }]);
    });

    test.each([
      [409, 'last_active_admin', 'At least one active administrator must remain.'],
      [409, 'oidc_account', 'signs in through the identity provider'],
      [409, 'own_account', 'You cannot do this to your own account.'],
      [400, 'invalid_request', 'The input is not valid.'],
    ])('says what is wrong when the server answers %i %s', async (status, code, text) => {
      const s = server('admin', { [`PATCH ${detail}`]: () => failure(status, code) });
      const { wrapper } = await boot(s, path);
      await wrapper.get('#display-name').setValue('Jane D.');
      await save(wrapper);
      expect(wrapper.get('[role=alert]').text()).toContain(text);
      expect(wrapper.text()).not.toContain('Saved.');
    });
  });

  describe('of the signed-in administrator', () => {
    const own = ownRecord();
    const ownDetail = `/api/v1/users/${own.id}`;
    const mine = (extra: Record<string, Handler> = {}) => server('admin', { [`GET ${ownDetail}`]: () => json(200, own), ...extra });

    test('cannot change its role or status, or be deleted, and says why', async () => {
      const { wrapper } = await boot(mine(), `/users/${own.id}`);
      expect(wrapper.get('#role').attributes('disabled')).toBeDefined();
      expect(wrapper.get('#status').attributes('disabled')).toBeDefined();
      expect(button(wrapper, 'Delete account')!.attributes('disabled')).toBeDefined();
      expect(wrapper.get('#role-hint').text()).toContain('You cannot do this to your own account.');
      expect(wrapper.get('.notice').text()).toContain('This is your account.');
      expect(wrapper.get('.notice a').attributes('href')).toBe('/account');
    });

    test('can still change its display name', async () => {
      const s = mine({ [`PATCH ${ownDetail}`]: () => json(200, ownRecord({ display_name: 'Ada A.' })) });
      const { wrapper } = await boot(s, `/users/${own.id}`);
      await wrapper.get('#display-name').setValue('Ada A.');
      await wrapper.findAll('form')[0]!.trigger('submit');
      await flushPromises();
      expect(requestsOf(s, 'PATCH').map((r) => r.body)).toEqual([{ display_name: 'Ada A.' }]);
    });

    test('has no button to remove its second factor, which is done in the account', async () => {
      const s = mine({ [`GET ${ownDetail}`]: () => json(200, ownRecord({ totp_enabled: true })) });
      const { wrapper } = await boot(s, `/users/${own.id}`);
      expect(button(wrapper, 'Remove the second factor')).toBeUndefined();
    });
  });

  describe('of the identity provider', () => {
    const sso = userRecord({ sign_in_method: 'oidc' });
    const one = (extra: Record<string, Handler> = {}) => server('admin', { [`GET ${detail}`]: () => json(200, sso), ...extra });

    test('has a role that follows the groups, and no password to reset', async () => {
      const { wrapper } = await boot(one(), path);
      expect(wrapper.get('#role').attributes('disabled')).toBeDefined();
      expect(wrapper.get('#role-hint').text()).toContain('follows the groups');
      expect(button(wrapper, 'New password reset link')).toBeUndefined();
      expect(wrapper.get('dl').text()).toContain('Managed by the identity provider');
    });
  });

  describe('given a link', () => {
    const answer = (url: string) => () => json(201, { url, expires_at: '2026-10-26T08:00:00Z' }, { 'Cache-Control': 'no-store' });

    test('offers an activation link to a pending account only', async () => {
      const pending = server('admin', { [`GET ${detail}`]: () => json(200, userRecord({ status: 'pending' })) });
      expect(button((await boot(pending, path)).wrapper, 'New activation link')).toBeDefined();
      document.body.innerHTML = '';
      expect(button((await boot(server(), path)).wrapper, 'New activation link')).toBeUndefined();
    });

    test('shows the new activation link once, and replaces it when another is issued', async () => {
      const second = `https://nyktus.example.com/activate#token=test-token-${'y'.repeat(33)}`;
      let next = link;
      const s = server('admin', {
        [`GET ${detail}`]: () => json(200, userRecord({ status: 'pending' })),
        [`POST ${detail}/activation-link`]: () => answer(next)(),
      });
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'New activation link')!.trigger('click');
      await flushPromises();
      expect(wrapper.get('[role=region]').text()).toContain(link);
      next = second;
      await button(wrapper, 'New activation link')!.trigger('click');
      await flushPromises();
      expect(wrapper.get('[role=region]').text()).toContain(second);
      expect(wrapper.html()).not.toContain(token);
      await wrapper.get('[role=region] button.button-primary').trigger('click');
      expect(wrapper.find('[role=region]').exists()).toBe(false);
    });

    test('takes the link away when the status of the account changes, which ends it', async () => {
      const s = server('admin', {
        [`GET ${detail}`]: () => json(200, userRecord({ status: 'pending' })),
        [`POST ${detail}/activation-link`]: answer(link),
        [`PATCH ${detail}`]: () => json(200, userRecord({ status: 'deactivated' })),
      });
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'New activation link')!.trigger('click');
      await flushPromises();
      expect(wrapper.find('[role=region]').exists()).toBe(true);
      await wrapper.findAll('form')[0]!.trigger('submit');
      await wrapper.get('#display-name').setValue('Jane Roe');
      await wrapper.findAll('form')[0]!.trigger('submit');
      await flushPromises();
      expect(requestsOf(s, 'PATCH')).toHaveLength(1);
      expect(wrapper.find('[role=region]').exists()).toBe(false);
      expect(wrapper.html()).not.toContain(token);
    });

    test('takes the old link away when asking for another fails', async () => {
      let fail = false;
      const s = server('admin', {
        [`GET ${detail}`]: () => json(200, userRecord({ status: 'pending' })),
        [`POST ${detail}/activation-link`]: () => (fail ? failure(500, 'internal_error') : answer(link)()),
      });
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'New activation link')!.trigger('click');
      await flushPromises();
      fail = true;
      await button(wrapper, 'New activation link')!.trigger('click');
      await flushPromises();
      expect(wrapper.find('[role=region]').exists()).toBe(false);
      expect(wrapper.html()).not.toContain(token);
    });

    test('offers a reset link to an active account with a password', async () => {
      const s = server('admin', { [`POST ${detail}/password-reset-link`]: answer('https://nyktus.example.com/reset-password#token=test-token-zzzz') });
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'New password reset link')!.trigger('click');
      await flushPromises();
      expect(requestsOf(s, 'POST').map((r) => r.url)).toEqual([`${detail}/password-reset-link`]);
      expect(wrapper.get('[role=region] h2').text()).toBe('Password reset link');
      expect(wrapper.get('[role=region]').text()).toContain('reset-password#token=');
    });

    test('offers no reset link to a deactivated account, and says that there is nothing to hand out', async () => {
      const s = server('admin', { [`GET ${detail}`]: () => json(200, userRecord({ status: 'deactivated' })) });
      const { wrapper } = await boot(s, path);
      expect(button(wrapper, 'New password reset link')).toBeUndefined();
      expect(wrapper.text()).toContain('Nothing to hand out for this account.');
    });

    test('keeps the link nowhere but the page', async () => {
      const s = server('admin', {
        [`GET ${detail}`]: () => json(200, userRecord({ status: 'pending' })),
        [`POST ${detail}/activation-link`]: answer(link),
      });
      const { wrapper, router } = await boot(s, path);
      await button(wrapper, 'New activation link')!.trigger('click');
      await flushPromises();
      const everything = JSON.stringify([
        globalThis.location.href,
        history.state,
        router.currentRoute.value,
        Object.entries(localStorage),
        Object.entries(sessionStorage),
        document.cookie,
        s.requests.map((r) => r.url),
      ]);
      expect(everything).not.toContain(token);
    });

    test('is gone when the user leaves the page', async () => {
      const s = server('admin', {
        [`GET ${detail}`]: () => json(200, userRecord({ status: 'pending' })),
        [`POST ${detail}/activation-link`]: answer(link),
      });
      const { wrapper, router } = await boot(s, path);
      await button(wrapper, 'New activation link')!.trigger('click');
      await flushPromises();
      await router.push('/users');
      await arrive(router, 'users');
      expect(wrapper.html()).not.toContain(token);
    });

    test('says so when the server refuses', async () => {
      const s = server('admin', { [`POST ${detail}/password-reset-link`]: () => failure(409, 'oidc_account') });
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'New password reset link')!.trigger('click');
      await flushPromises();
      expect(wrapper.get('[role=alert]').text()).toContain('signs in through the identity provider');
      expect(wrapper.find('[role=region]').exists()).toBe(false);
    });
  });

  describe('with a second factor to remove', () => {
    const secured = () => server('admin', { [`GET ${detail}`]: () => json(200, userRecord({ totp_enabled: true })) });
    const open = async (s: ReturnType<typeof server>) => {
      const app = await boot(s, path);
      await button(app.wrapper, 'Remove the second factor')!.trigger('click');
      await flushPromises();
      return app;
    };

    test('is only offered when there is one', async () => {
      expect(button((await boot(server(), path)).wrapper, 'Remove the second factor')).toBeUndefined();
    });

    test('asks for the password of the administrator, and sends nothing before it', async () => {
      const s = secured();
      const { wrapper } = await open(s);
      expect(dialog(wrapper).get('h2').text()).toBe('Remove the second factor?');
      expect(dialog(wrapper).find('input[type=password]').exists()).toBe(true);
      expect(requestsOf(s, 'PATCH')).toHaveLength(0);
    });

    test('sends the removal with the password, and shows the account without a factor', async () => {
      const s = secured();
      s.on(`PATCH ${detail}`, () => json(200, userRecord({ totp_enabled: false })));
      const { wrapper } = await open(s);
      await dialog(wrapper).get('input[type=password]').setValue(typed);
      await dialog(wrapper).get('.button-primary').trigger('click');
      await flushPromises();
      expect(requestsOf(s, 'PATCH').map((r) => r.body)).toEqual([{ totp_enabled: false, password: typed }]);
      expect(wrapper.get('dl').text()).toContain('No second factor');
      expect(button(wrapper, 'Remove the second factor')).toBeUndefined();
      expect(document.body.innerHTML).not.toContain(typed);
    });

    test('takes an earlier error and a saved note away when it is asked again', async () => {
      const s = secured();
      s.on(`PATCH ${detail}`, () => failure(500, 'internal_error'));
      const { wrapper } = await open(s);
      await dialog(wrapper).get('input[type=password]').setValue(typed);
      await dialog(wrapper).get('.button-primary').trigger('click');
      await flushPromises();
      expect(wrapper.find('[role=alert]').exists()).toBe(true);
      s.on(`PATCH ${detail}`, () => json(200, userRecord({ totp_enabled: false })));
      await button(wrapper, 'Remove the second factor')!.trigger('click');
      await flushPromises();
      expect(wrapper.findAll('[role=alert]').filter((e) => e.element.closest('dialog') === null)).toHaveLength(0);
      await dialog(wrapper).get('input[type=password]').setValue(typed);
      await dialog(wrapper).get('.button-primary').trigger('click');
      await flushPromises();
      expect(wrapper.find('[role=alert]').exists()).toBe(false);
      expect(wrapper.text()).toContain('Saved.');
    });

    test('says so in the dialog when the password is wrong, and empties the field', async () => {
      const s = secured();
      s.on(`PATCH ${detail}`, () => failure(403, 'wrong_password'));
      const { wrapper } = await open(s);
      await dialog(wrapper).get('input[type=password]').setValue(typed);
      await dialog(wrapper).get('.button-primary').trigger('click');
      await flushPromises();
      expect(dialog(wrapper).get('[role=alert]').text()).toBe('The password is wrong.');
      expect((dialog(wrapper).get('input[type=password]').element as HTMLInputElement).value).toBe('');
    });

    test('closes the dialog and says why when the server refuses otherwise', async () => {
      const s = secured();
      s.on(`PATCH ${detail}`, () => failure(409, 'own_account'));
      const { wrapper } = await open(s);
      await dialog(wrapper).get('input[type=password]').setValue(typed);
      await dialog(wrapper).get('.button-primary').trigger('click');
      await flushPromises();
      expect(wrapper.find('dialog[open]').exists()).toBe(false);
      expect(wrapper.get('section > [role=alert]').text()).toContain('You cannot do this to your own account.');
    });
  });

  describe('deleted', () => {
    test('only after the user confirms, and the list follows', async () => {
      const s = server('admin', { [`DELETE ${detail}`]: noContent });
      const { wrapper, router } = await boot(s, path);
      await button(wrapper, 'Delete account')!.trigger('click');
      await flushPromises();
      expect(dialog(wrapper).get('h2').text()).toBe('Delete this account?');
      expect(requestsOf(s, 'DELETE')).toHaveLength(0);
      await dialog(wrapper).get('.danger').trigger('click');
      await flushPromises();
      expect(requestsOf(s, 'DELETE')).toHaveLength(1);
      await arrive(router, 'users');
    });

    test('says so when the last administrator would go', async () => {
      const s = server('admin', { [`GET ${detail}`]: () => json(200, userRecord({ role: 'admin' })), [`DELETE ${detail}`]: () => failure(409, 'last_active_admin') });
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'Delete account')!.trigger('click');
      await flushPromises();
      await dialog(wrapper).get('.danger').trigger('click');
      await flushPromises();
      expect(wrapper.find('dialog[open]').exists()).toBe(false);
      expect(wrapper.get('section > [role=alert]').text()).toBe('At least one active administrator must remain.');
    });
  });
});

describe('the pages in German', () => {
  test('speak German and keep the values as they are', async () => {
    const { wrapper, i18n } = await boot(server(), path);
    i18n.setLocale('de');
    await flushPromises();
    expect(wrapper.text()).toContain('Konto \u00E4ndern');
    expect(wrapper.text()).toContain('jane@example.com');
  });
});
