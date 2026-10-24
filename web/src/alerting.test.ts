// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises } from '@vue/test-utils';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { arrive, boot } from './testing/boot';
import {
  alertChannel,
  alertDelivery,
  channelId,
  deliveryId,
  emailChannel,
  failure,
  fakeServer,
  incident,
  incidentId,
  json,
  noContent,
  sessionBody,
  type Handler,
} from './testing/fakeServer';

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  document.body.innerHTML = '';
  history.replaceState(null, '', '/');
});

type Role = 'admin' | 'user' | 'viewer';
type Wrapper = Awaited<ReturnType<typeof boot>>['wrapper'];

const detail = `/api/v1/alert-channels/${channelId}`;
const path = `/alert-channels/${channelId}`;
// Plainly made up, so that a scan for secrets does not take them for real ones.
const secretUrl = 'https://hooks.example.com/services/test-secret-xxxxxxxx';
const otherUrl = 'https://hooks.example.com/services/test-secret-yyyyyyyy';
const headerSecret = 'Bearer test-secret-zzzzzzzz';
const typed = 'test-password-not-real';

function server(role: Role = 'admin', extra: Record<string, Handler> = {}, method: 'password' | 'oidc' = 'password') {
  return fakeServer({
    'GET /api/v1/session': () => json(200, sessionBody(role, 'Ada Admin', method)),
    'GET /api/v1/alert-channels': () => json(200, { alert_channels: [alertChannel(), emailChannel(), alertChannel({ id: 'cafe0000-3333-4222-8333-944444444444', name: 'Old', type: 'slack', enabled: false, header_name: null, target: 'https://hooks.slack.com' })] }),
    [`GET ${detail}`]: () => json(200, alertChannel()),
    ...extra,
  });
}

const requestsOf = (s: ReturnType<typeof server>, method: string) => s.requests.filter((r) => r.method === method);
const button = (wrapper: Wrapper, label: string) => wrapper.findAll('button').find((b) => b.text() === label);
const dialog = (wrapper: Wrapper) => wrapper.get('dialog[open]');

async function enter(wrapper: Wrapper, password = typed): Promise<void> {
  await dialog(wrapper).get('input[type=password]').setValue(password);
}

async function confirm(wrapper: Wrapper): Promise<void> {
  await dialog(wrapper).get('.button-primary').trigger('click');
  await flushPromises();
}

/** The places where a secret must never be found, apart from the request that carries it. */
function expectNowhere(secret: string, s: ReturnType<typeof server>, router?: { currentRoute: { value: { fullPath: string } } }): void {
  expect(document.body.innerHTML).not.toContain(secret);
  for (const input of document.querySelectorAll('input, textarea')) {
    expect((input as HTMLInputElement).value, (input as HTMLInputElement).id).not.toContain(secret);
  }
  expect(globalThis.location.href).not.toContain(secret);
  expect(JSON.stringify(history.state ?? null)).not.toContain(secret);
  expect(JSON.stringify({ ...localStorage })).not.toContain(secret);
  expect(JSON.stringify({ ...sessionStorage })).not.toContain(secret);
  if (router) {
    expect(router.currentRoute.value.fullPath).not.toContain(secret);
  }
  for (const request of s.requests) {
    expect(request.url).not.toContain(secret);
  }
}

describe('the list of alert channels', () => {
  test('shows each channel with its type, state and target, and the recipients of a mail channel', async () => {
    const { wrapper } = await boot(server(), '/alert-channels');
    const rows = wrapper.findAll('tbody tr');
    expect(rows).toHaveLength(3);
    expect(rows[0]?.text()).toContain('SOAR');
    expect(rows[0]?.text()).toContain('Webhook');
    expect(rows[0]?.text()).toContain('Enabled');
    expect(rows[0]?.text()).toContain('https://soar.example.com');
    expect(rows[1]?.text()).toContain('Email');
    expect(rows[1]?.text()).toContain('soc@example.com, it@example.com');
    expect(rows[2]?.text()).toContain('Disabled');
    expect(rows[0]?.get('a').attributes('href')).toBe(path);
  });

  test('offers a new channel to an administrator', async () => {
    const { wrapper } = await boot(server(), '/alert-channels');
    expect(wrapper.get('.page-head a.button').attributes('href')).toBe('/alert-channels/new');
  });

  test('says so when there are none, and when they cannot be loaded', async () => {
    const none = await boot(server('admin', { 'GET /api/v1/alert-channels': () => json(200, { alert_channels: [] }) }), '/alert-channels');
    expect(none.wrapper.text()).toContain('Without one, incidents raise no alert.');
    document.body.innerHTML = '';
    const failed = await boot(server('admin', { 'GET /api/v1/alert-channels': () => failure(500, 'internal_error') }), '/alert-channels');
    expect(failed.wrapper.get('[role=alert]').text()).toContain('The alert channels could not be loaded.');
  });

  test('shows a name that is markup as text', async () => {
    const hostile = alertChannel({ name: '<img src=x onerror=alert(1)>' });
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/alert-channels': () => json(200, { alert_channels: [hostile] }) }), '/alert-channels');
    expect(wrapper.find('img[src=x]').exists()).toBe(false);
    expect(wrapper.get('tbody a').text()).toBe('<img src=x onerror=alert(1)>');
  });

  test.each(['user', 'viewer'] as const)('is not in the navigation of the role %s, and its pages do not open', async (role) => {
    const { wrapper, router } = await boot(server(role), '/');
    expect(wrapper.findAll('nav a').map((a) => a.text())).not.toContain('Alert channels');
    for (const target of ['/alert-channels', '/alert-channels/new', path]) {
      await router.push(target);
      await arrive(router, 'forbidden');
    }
  });

  test('is in the navigation of an administrator', async () => {
    const { wrapper } = await boot(server(), '/');
    expect(wrapper.findAll('nav a').map((a) => a.text())).toContain('Alert channels');
  });
});

describe('a new alert channel', () => {
  const create = '/alert-channels/new';
  const created = alertChannel({ id: 'cafe0000-9999-4222-8333-944444444444' });

  async function fill(wrapper: Wrapper, values: Record<string, string>): Promise<void> {
    for (const [selector, value] of Object.entries(values)) {
      await wrapper.get(selector).setValue(value);
    }
  }

  const submit = async (wrapper: Wrapper) => {
    await wrapper.get('form.narrow').trigger('submit');
    await flushPromises();
  };

  function creating(extra: Record<string, Handler> = {}, method: 'password' | 'oidc' = 'password') {
    return server('admin', { 'POST /api/v1/alert-channels': () => json(201, created), [`GET /api/v1/alert-channels/${created.id}`]: () => json(200, created), ...extra }, method);
  }

  test('asks for the password first, and sends nothing before it', async () => {
    const s = creating();
    const { wrapper } = await boot(s, create);
    await fill(wrapper, { '#channel-name': ' SOAR ', '#channel-url': secretUrl });
    await submit(wrapper);
    expect(dialog(wrapper).get('h2').text()).toBe('Create this alert channel?');
    expect(requestsOf(s, 'POST')).toHaveLength(0);
    expect(dialog(wrapper).get('input[type=password]').attributes('autocomplete')).toBe('current-password');
  });

  test.each([
    ['a name of spaces', { '#channel-name': '   ', '#channel-url': secretUrl }, 'Enter a name.'],
    ['a URL of spaces', { '#channel-name': 'SOAR', '#channel-url': '   ' }, 'Enter the URL.'],
  ])('asks again for %s, before the password', async (_what, values, said) => {
    const s = creating();
    const { wrapper } = await boot(s, create);
    await fill(wrapper, values);
    await submit(wrapper);
    expect(wrapper.get('[role=alert]').text()).toBe(said);
    expect(wrapper.find('dialog[open]').exists()).toBe(false);
    expect(requestsOf(s, 'POST')).toHaveLength(0);
  });

  test('sends the channel with the password, and goes to it', async () => {
    const s = creating();
    const { wrapper, router } = await boot(s, create);
    await fill(wrapper, { '#channel-name': ' SOAR ', '#channel-url': ` ${secretUrl} ` });
    await submit(wrapper);
    await enter(wrapper);
    await confirm(wrapper);
    expect(requestsOf(s, 'POST').map((r) => r.body)).toEqual([{ name: 'SOAR', type: 'webhook', enabled: true, url: secretUrl, password: typed }]);
    await arrive(router, 'alert-channel');
    expect(router.currentRoute.value.params.id).toBe(created.id);
    expect(wrapper.text()).toContain('The alert channel has been created.');
  });

  test('sends a header of a webhook with both its name and its value', async () => {
    const s = creating();
    const { wrapper } = await boot(s, create);
    await fill(wrapper, { '#channel-name': 'SOAR', '#channel-url': secretUrl, '#channel-header-name': ' Authorization ', '#channel-header-value': headerSecret });
    await submit(wrapper);
    await enter(wrapper);
    await confirm(wrapper);
    expect(requestsOf(s, 'POST')[0]?.body).toMatchObject({ header: { name: 'Authorization', value: headerSecret } });
  });

  test('leaves the header out when the type was changed after it was typed', async () => {
    const s = creating();
    const { wrapper } = await boot(s, create);
    await fill(wrapper, { '#channel-name': 'Chat', '#channel-url': secretUrl, '#channel-header-name': 'Authorization', '#channel-header-value': headerSecret });
    await wrapper.get('#channel-type').setValue('slack');
    await submit(wrapper);
    await enter(wrapper);
    await confirm(wrapper);
    expect(requestsOf(s, 'POST')[0]?.body).not.toHaveProperty('header');
  });

  test('hides the value of the header while it is typed', async () => {
    const { wrapper } = await boot(creating(), create);
    expect(wrapper.get('#channel-header-value').attributes('type')).toBe('password');
  });

  test('does not ask when only one half of the header is given', async () => {
    const s = creating();
    const { wrapper } = await boot(s, create);
    await fill(wrapper, { '#channel-name': 'SOAR', '#channel-url': secretUrl, '#channel-header-name': 'Authorization' });
    await submit(wrapper);
    expect(wrapper.find('dialog[open]').exists()).toBe(false);
    expect(wrapper.get('[role=alert]').text()).toBe('Give the name and the value of the header, or neither.');
    await fill(wrapper, { '#channel-header-name': '', '#channel-header-value': headerSecret });
    await submit(wrapper);
    expect(wrapper.find('dialog[open]').exists()).toBe(false);
  });

  test('offers no header for Slack and Teams, and no URL for mail', async () => {
    const { wrapper } = await boot(creating(), create);
    await wrapper.get('#channel-type').setValue('slack');
    expect(wrapper.find('#channel-header-name').exists()).toBe(false);
    expect(wrapper.find('#channel-url').exists()).toBe(true);
    await wrapper.get('#channel-type').setValue('teams');
    expect(wrapper.find('#channel-header-name').exists()).toBe(false);
    await wrapper.get('#channel-type').setValue('email');
    expect(wrapper.find('#channel-url').exists()).toBe(false);
    expect(wrapper.find('#channel-recipients').exists()).toBe(true);
    await wrapper.get('#channel-type').setValue('webhook');
    expect(wrapper.find('#channel-header-name').exists()).toBe(true);
  });

  test('sends the recipients of a mail channel, and no URL', async () => {
    const s = creating();
    const { wrapper } = await boot(s, create);
    await wrapper.get('#channel-type').setValue('email');
    await fill(wrapper, { '#channel-name': 'SOC', '#channel-recipients': 'soc@example.com\nit@example.com, ops@example.org' });
    await wrapper.get('#channel-enabled').setValue(false);
    await submit(wrapper);
    await enter(wrapper);
    await confirm(wrapper);
    expect(requestsOf(s, 'POST').map((r) => r.body)).toEqual([
      { name: 'SOC', type: 'email', enabled: false, recipients: ['soc@example.com', 'it@example.com', 'ops@example.org'], password: typed },
    ]);
  });

  test.each([
    ['nothing', ''],
    ['a text that is no address', 'soc'],
    ['an address twice', 'soc@example.com SOC@example.com'],
    ['eleven addresses', Array.from({ length: 11 }, (_, i) => `a${i}@example.com`).join(' ')],
  ])('does not ask for a mail channel with %s', async (_, recipients) => {
    const { wrapper } = await boot(creating(), create);
    await wrapper.get('#channel-type').setValue('email');
    await fill(wrapper, { '#channel-name': 'SOC', '#channel-recipients': recipients });
    await submit(wrapper);
    expect(wrapper.find('dialog[open]').exists()).toBe(false);
    expect(wrapper.findAll('form.narrow [role=alert]').map((a) => a.text()).join(' ')).toContain('between 1 and 10 different addresses');
  });

  test('does not keep the password, in the field or anywhere else, and the secrets are gone with the form', async () => {
    const s = creating();
    const { wrapper, router } = await boot(s, create);
    await fill(wrapper, { '#channel-name': 'SOAR', '#channel-url': secretUrl, '#channel-header-name': 'Authorization', '#channel-header-value': headerSecret });
    await submit(wrapper);
    await enter(wrapper);
    await confirm(wrapper);
    await arrive(router, 'alert-channel');
    for (const secret of [typed, secretUrl, headerSecret]) {
      expect(document.body.innerHTML).not.toContain(secret);
      expect(globalThis.location.href).not.toContain(secret);
      expect(JSON.stringify(history.state ?? null)).not.toContain(secret);
      expect(JSON.stringify({ ...localStorage })).not.toContain(secret);
      expect(JSON.stringify({ ...sessionStorage })).not.toContain(secret);
      expect(router.currentRoute.value.fullPath).not.toContain(secret);
      expect(s.requests.filter((r) => r.method === 'GET').map((r) => r.url).join('\n')).not.toContain(secret);
    }
  });

  describe('when the password is not right', () => {
    test('says so in the dialog, keeps it open, and empties the field', async () => {
      const s = creating({ 'POST /api/v1/alert-channels': () => failure(403, 'wrong_password') });
      const { wrapper } = await boot(s, create);
      await fill(wrapper, { '#channel-name': 'SOAR', '#channel-url': secretUrl });
      await submit(wrapper);
      await enter(wrapper);
      await confirm(wrapper);
      expect(dialog(wrapper).get('[role=alert]').text()).toBe('The password is wrong.');
      expect((dialog(wrapper).get('input[type=password]').element as HTMLInputElement).value).toBe('');
      expect(wrapper.find('form.narrow > [role=alert]').exists()).toBe(false);
    });

    test('lets the user try again, and the second try goes through', async () => {
      let attempt = 0;
      const s = creating({
        'POST /api/v1/alert-channels': () => (++attempt === 1 ? failure(403, 'wrong_password') : json(201, created)),
      });
      const { wrapper, router } = await boot(s, create);
      await fill(wrapper, { '#channel-name': 'SOAR', '#channel-url': secretUrl });
      await submit(wrapper);
      await enter(wrapper, 'wrong');
      await confirm(wrapper);
      await enter(wrapper, typed);
      await confirm(wrapper);
      expect(requestsOf(s, 'POST').map((r) => (r.body as { password: string }).password)).toEqual(['wrong', typed]);
      await arrive(router, 'alert-channel');
    });

    test('says how long the account is locked', async () => {
      const s = creating({ 'POST /api/v1/alert-channels': () => failure(403, 'account_locked', { 'Retry-After': '600' }) });
      const { wrapper } = await boot(s, create);
      await fill(wrapper, { '#channel-name': 'SOAR', '#channel-url': secretUrl });
      await submit(wrapper);
      await enter(wrapper);
      await confirm(wrapper);
      expect(dialog(wrapper).get('[role=alert]').text()).toBe('The account is locked. Try again in 10 minutes.');
      expect((dialog(wrapper).get('input[type=password]').element as HTMLInputElement).value).toBe('');
    });

    test('forgets a password that was typed and not sent, when the dialog is closed', async () => {
      const s = creating();
      const { wrapper } = await boot(s, create);
      await fill(wrapper, { '#channel-name': 'SOAR', '#channel-url': secretUrl });
      await submit(wrapper);
      await enter(wrapper);
      await dialog(wrapper).get('.button-ghost').trigger('click');
      await flushPromises();
      await submit(wrapper);
      expect((dialog(wrapper).get('input[type=password]').element as HTMLInputElement).value).toBe('');
      expect(requestsOf(s, 'POST')).toHaveLength(0);
    });

    test('sends the request once when it is confirmed twice while it is on its way', async () => {
      let release: () => void = () => {};
      const slow = new Promise<void>((resolve) => {
        release = resolve;
      });
      const s = creating({
        'POST /api/v1/alert-channels': async () => {
          await slow;
          return json(201, created);
        },
      });
      const { wrapper } = await boot(s, create);
      await fill(wrapper, { '#channel-name': 'SOAR', '#channel-url': secretUrl });
      await submit(wrapper);
      await enter(wrapper);
      await dialog(wrapper).get('form').trigger('submit');
      await dialog(wrapper).get('form').trigger('submit');
      await flushPromises();
      expect(requestsOf(s, 'POST')).toHaveLength(1);
      release();
      await flushPromises();
    });

    test('does not send an empty password', async () => {
      const s = creating();
      const { wrapper } = await boot(s, create);
      await fill(wrapper, { '#channel-name': 'SOAR', '#channel-url': secretUrl });
      await submit(wrapper);
      await confirm(wrapper);
      expect(requestsOf(s, 'POST')).toHaveLength(0);
      expect(dialog(wrapper).get('[role=alert]').text()).toBe('Enter your password.');
    });

    test('forgets the password and the message when the dialog is closed', async () => {
      const s = creating({ 'POST /api/v1/alert-channels': () => failure(403, 'wrong_password') });
      const { wrapper } = await boot(s, create);
      await fill(wrapper, { '#channel-name': 'SOAR', '#channel-url': secretUrl });
      await submit(wrapper);
      await enter(wrapper);
      await confirm(wrapper);
      await dialog(wrapper).get('.button-ghost').trigger('click');
      await flushPromises();
      expect(wrapper.find('dialog[open]').exists()).toBe(false);
      await submit(wrapper);
      expect(dialog(wrapper).find('[role=alert]').exists()).toBe(false);
      expect((dialog(wrapper).get('input[type=password]').element as HTMLInputElement).value).toBe('');
    });
  });

  describe('when the server refuses the channel', () => {
    test.each([
      [422, 'target_not_allowed', 'The URL is not allowed.'],
      [422, 'header_not_allowed', 'Only a webhook can have a header.'],
      [409, 'name_taken', 'Another alert channel has this name.'],
      [409, 'too_many_alert_channels', 'at most 20 alert channels'],
      [400, 'invalid_request', 'The input is not valid.'],
    ])('says what is wrong for %i %s, closes the dialog and keeps the form', async (status, code, text) => {
      const s = creating({ 'POST /api/v1/alert-channels': () => failure(status, code) });
      const { wrapper } = await boot(s, create);
      await fill(wrapper, { '#channel-name': 'SOAR', '#channel-url': secretUrl });
      await submit(wrapper);
      await enter(wrapper);
      await confirm(wrapper);
      expect(wrapper.find('dialog[open]').exists()).toBe(false);
      expect(wrapper.get('section > [role=alert]').text()).toContain(text);
      expect((wrapper.get('#channel-name').element as HTMLInputElement).value).toBe('SOAR');
    });
  });

  describe('for an account of the identity provider', () => {
    test('asks for no password and sends none', async () => {
      const s = creating({}, 'oidc');
      const { wrapper, router } = await boot(s, create);
      await fill(wrapper, { '#channel-name': 'SOAR', '#channel-url': secretUrl });
      await submit(wrapper);
      expect(dialog(wrapper).find('input[type=password]').exists()).toBe(false);
      expect(dialog(wrapper).text()).toContain('you confirm by signing in there again');
      await confirm(wrapper);
      expect(requestsOf(s, 'POST')[0]?.body).not.toHaveProperty('password');
      await arrive(router, 'alert-channel');
    });

    test('offers to sign in again when the server asks for it, and goes back to this page', async () => {
      const assign = vi.spyOn(globalThis.location, 'assign').mockImplementation(() => {});
      const s = creating({ 'POST /api/v1/alert-channels': () => failure(403, 'reauthentication_required') }, 'oidc');
      const { wrapper } = await boot(s, create);
      await fill(wrapper, { '#channel-name': 'SOAR', '#channel-url': secretUrl });
      await submit(wrapper);
      await confirm(wrapper);
      expect(dialog(wrapper).get('[role=alert]').text()).toContain('Sign in again at your identity provider');
      expect(dialog(wrapper).get('.button-primary').text()).toBe('Sign in again');
      expect(assign).not.toHaveBeenCalled();
      await dialog(wrapper).get('.button-primary').trigger('click');
      expect(assign).toHaveBeenCalledExactlyOnceWith('/api/v1/oidc/reauthenticate?return_to=%2Falert-channels%2Fnew');
      expect(requestsOf(s, 'POST')).toHaveLength(1);
    });

    test('is back at the usual button when the dialog is closed and opened again', async () => {
      const s = creating({ 'POST /api/v1/alert-channels': () => failure(403, 'reauthentication_required') }, 'oidc');
      const { wrapper } = await boot(s, create);
      await fill(wrapper, { '#channel-name': 'SOAR', '#channel-url': secretUrl });
      await submit(wrapper);
      await confirm(wrapper);
      expect(dialog(wrapper).get('.button-primary').text()).toBe('Sign in again');
      await dialog(wrapper).get('.button-ghost').trigger('click');
      await flushPromises();
      await submit(wrapper);
      expect(dialog(wrapper).get('.button-primary').text()).toBe('Create channel');
      expect(dialog(wrapper).find('[role=alert]').exists()).toBe(false);
    });

    test('lets go of the note about the failed confirmation when the user tries again', async () => {
      history.replaceState(null, '', '/alert-channels/new#error=reauthentication');
      const { wrapper } = await boot(creating({}, 'oidc'), create);
      expect(wrapper.find('p.notice-error[role=alert]').exists()).toBe(true);
      await fill(wrapper, { '#channel-name': 'SOAR', '#channel-url': secretUrl });
      await submit(wrapper);
      expect(wrapper.find('dialog[open]').exists()).toBe(true);
      expect(wrapper.findAll('[role=alert]').filter((e) => e.element.closest('dialog') === null)).toHaveLength(0);
    });

    test('says so when the identity provider could not confirm the user, and removes the fragment', async () => {
      history.replaceState(null, '', '/alert-channels/new#error=reauthentication');
      const { wrapper } = await boot(creating({}, 'oidc'), create);
      expect(wrapper.get('[role=alert]').text()).toBe('The identity provider could not confirm you. Try again.');
      expect(globalThis.location.hash).toBe('');
    });
  });

  test('does not show the message of the server', async () => {
    const s = creating({ 'POST /api/v1/alert-channels': () => failure(500, 'internal_error') });
    const { wrapper } = await boot(s, create);
    await fill(wrapper, { '#channel-name': 'SOAR', '#channel-url': secretUrl });
    await submit(wrapper);
    await enter(wrapper);
    await confirm(wrapper);
    expect(wrapper.get('section > [role=alert]').text()).toBe('Something went wrong on the server.');
  });
});

describe('an alert channel', () => {
  test('shows its target and the name of its header, and no secret', async () => {
    const { wrapper } = await boot(server(), path);
    const text = wrapper.get('dl').text();
    expect(text).toContain('https://soar.example.com');
    expect(text).toContain('Authorization');
    expect(text).toContain('never shown again');
  });

  test('shows the recipients of a mail channel', async () => {
    const mail = emailChannel();
    const { wrapper } = await boot(server('admin', { [`GET /api/v1/alert-channels/${mail.id}`]: () => json(200, mail) }), `/alert-channels/${mail.id}`);
    expect(wrapper.get('dl').text()).toContain('soc@example.com, it@example.com');
    expect(wrapper.get('dl').text()).not.toContain('never shown again');
  });

  test('says when it does not exist, and when it cannot be loaded', async () => {
    const gone = await boot(server('admin', { [`GET ${detail}`]: () => failure(404, 'not_found') }), path);
    expect(gone.wrapper.text()).toContain('This does not exist.');
    document.body.innerHTML = '';
    const failed = await boot(server('admin', { [`GET ${detail}`]: () => failure(500, 'internal_error') }), path);
    expect(failed.wrapper.get('[role=alert]').text()).toBe('Something went wrong on the server.');
  });

  describe('renamed', () => {
    test('with no password, and only the name', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => json(200, alertChannel({ name: 'SIEM' })) });
      const { wrapper } = await boot(s, path);
      await wrapper.get('#channel-name').setValue(' SIEM ');
      await wrapper.findAll('form')[0]!.trigger('submit');
      await flushPromises();
      expect(requestsOf(s, 'PATCH').map((r) => r.body)).toEqual([{ name: 'SIEM' }]);
      expect(wrapper.find('dialog[open]').exists()).toBe(false);
      expect(wrapper.get('h1').text()).toBe('SIEM');
      expect(wrapper.text()).toContain('Saved.');
    });

    test('asks for a name that is more than spaces, and sends nothing', async () => {
      const s = server();
      const { wrapper } = await boot(s, path);
      await wrapper.get('#channel-name').setValue('   ');
      await wrapper.findAll('form')[0]!.trigger('submit');
      await flushPromises();
      expect(wrapper.get('[role=alert]').text()).toBe('Enter a name.');
      expect(requestsOf(s, 'PATCH')).toHaveLength(0);
    });

    test('does not discard what was typed for another change', async () => {
      const mail = emailChannel();
      const s = server('admin', { [`GET /api/v1/alert-channels/${mail.id}`]: () => json(200, mail), [`PATCH /api/v1/alert-channels/${mail.id}`]: () => json(200, emailChannel({ name: 'Renamed' })) });
      const { wrapper } = await boot(s, `/alert-channels/${mail.id}`);
      await wrapper.get('#channel-recipients').setValue('typed@example.com');
      await wrapper.get('#channel-name').setValue('Renamed');
      await wrapper.findAll('form')[0]!.trigger('submit');
      await flushPromises();
      expect(wrapper.get('h1').text()).toBe('Renamed');
      expect((wrapper.get('#channel-recipients').element as HTMLTextAreaElement).value).toBe('typed@example.com');
    });

    test('says that the channel was created only until the first thing that is done with it', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => json(200, alertChannel({ name: 'SIEM' })) });
      const { wrapper, router } = await boot(s, `${path}?created=1`);
      expect(wrapper.text()).toContain('The alert channel has been created.');
      await wrapper.get('#channel-name').setValue('SIEM');
      await wrapper.findAll('form')[0]!.trigger('submit');
      await flushPromises();
      expect(wrapper.text()).not.toContain('The alert channel has been created.');
      expect(router.currentRoute.value.fullPath).toBe(path);
    });

    test('sends nothing when the name did not change', async () => {
      const s = server();
      const { wrapper } = await boot(s, path);
      await wrapper.findAll('form')[0]!.trigger('submit');
      await flushPromises();
      expect(requestsOf(s, 'PATCH')).toHaveLength(0);
    });

    test('says when the name is taken', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => failure(409, 'name_taken') });
      const { wrapper } = await boot(s, path);
      await wrapper.get('#channel-name').setValue('Other');
      await wrapper.findAll('form')[0]!.trigger('submit');
      await flushPromises();
      expect(wrapper.get('section > [role=alert]').text()).toBe('Another alert channel has this name.');
    });
  });

  describe('disabled and enabled', () => {
    test('with the password, and the badge follows the server', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => json(200, alertChannel({ enabled: false })) });
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'Disable')!.trigger('click');
      await flushPromises();
      expect(dialog(wrapper).get('h2').text()).toBe('Disable this channel?');
      expect(requestsOf(s, 'PATCH')).toHaveLength(0);
      await enter(wrapper);
      await confirm(wrapper);
      expect(requestsOf(s, 'PATCH').map((r) => r.body)).toEqual([{ enabled: false, password: typed }]);
      expect(wrapper.get('.badges').text()).toContain('Disabled');
      expect(button(wrapper, 'Enable')).toBeDefined();
      expect(button(wrapper, 'Disable')).toBeUndefined();
    });

    test('names what the dialog is for', async () => {
      const off = server('admin', { [`GET ${detail}`]: () => json(200, alertChannel({ enabled: false })) });
      const { wrapper } = await boot(off, path);
      await button(wrapper, 'Enable')!.trigger('click');
      await flushPromises();
      expect(dialog(wrapper).get('h2').text()).toBe('Enable this channel?');
    });

    test('enabling again reminds the user that the target may have changed hands', async () => {
      const s = server('admin', { [`GET ${detail}`]: () => json(200, alertChannel({ enabled: false })) });
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'Enable')!.trigger('click');
      await flushPromises();
      expect(dialog(wrapper).text()).toContain('can change hands');
    });

    test('does nothing when the user cancels', async () => {
      const s = server();
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'Disable')!.trigger('click');
      await flushPromises();
      await dialog(wrapper).get('.button-ghost').trigger('click');
      await flushPromises();
      expect(requestsOf(s, 'PATCH')).toHaveLength(0);
      expect(wrapper.find('dialog[open]').exists()).toBe(false);
    });
  });

  describe('given a new target', () => {
    const replace = async (wrapper: Wrapper) => {
      await wrapper.findAll('form')[1]!.trigger('submit');
      await flushPromises();
    };

    test('sends the new URL with the password, and empties the field once it is written', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => json(200, alertChannel({ updated_at: '2026-10-22T09:00:00Z' })) });
      const { wrapper, router } = await boot(s, path);
      await wrapper.get('#channel-url').setValue(` ${secretUrl} `);
      await replace(wrapper);
      expect(requestsOf(s, 'PATCH')).toHaveLength(0);
      await enter(wrapper);
      await confirm(wrapper);
      expect(requestsOf(s, 'PATCH').map((r) => r.body)).toEqual([{ url: secretUrl, password: typed }]);
      expect((wrapper.get('#channel-url').element as HTMLInputElement).value).toBe('');
      expect(wrapper.text()).toContain('Saved.');
      expectNowhere(secretUrl, s, router);
      expectNowhere(typed, s, router);
    });

    test('does not discard a new name that was typed and not sent', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => json(200, alertChannel({ updated_at: '2026-10-22T09:00:00Z' })) });
      const { wrapper } = await boot(s, path);
      await wrapper.get('#channel-name').setValue('Typed, not sent');
      await wrapper.get('#channel-url').setValue(secretUrl);
      await replace(wrapper);
      await enter(wrapper);
      await confirm(wrapper);
      expect(requestsOf(s, 'PATCH')).toHaveLength(1);
      expect((wrapper.get('#channel-name').element as HTMLInputElement).value).toBe('Typed, not sent');
    });

    test('replaces the header, and keeps the URL as it is', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => json(200, alertChannel({ header_name: 'X-Token' })) });
      const { wrapper, router } = await boot(s, path);
      await wrapper.get('#channel-header-name').setValue('X-Token');
      await wrapper.get('#channel-header-value').setValue(headerSecret);
      await replace(wrapper);
      await enter(wrapper);
      await confirm(wrapper);
      expect(requestsOf(s, 'PATCH').map((r) => r.body)).toEqual([{ header: { name: 'X-Token', value: headerSecret }, password: typed }]);
      expect((wrapper.get('#channel-header-value').element as HTMLInputElement).value).toBe('');
      expect(wrapper.get('dl').text()).toContain('X-Token');
      expectNowhere(headerSecret, s, router);
    });

    test('removes the header with null', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => json(200, alertChannel({ header_name: null })) });
      const { wrapper } = await boot(s, path);
      await wrapper.get('#channel-header-remove').setValue(true);
      await replace(wrapper);
      await enter(wrapper);
      await confirm(wrapper);
      expect(requestsOf(s, 'PATCH').map((r) => r.body)).toEqual([{ header: null, password: typed }]);
      expect(wrapper.find('#channel-header-remove').exists()).toBe(false);
    });

    test('hides the value of the header while it is typed, and cannot type one while removing it', async () => {
      const { wrapper } = await boot(server(), path);
      expect(wrapper.get('#channel-header-value').attributes('type')).toBe('password');
      expect(wrapper.get('#channel-header-name').attributes('disabled')).toBeUndefined();
      await wrapper.get('#channel-header-remove').setValue(true);
      expect(wrapper.get('#channel-header-name').attributes('disabled')).toBeDefined();
      expect(wrapper.get('#channel-header-value').attributes('disabled')).toBeDefined();
    });

    test('does not ask when only half of the header is given, or when nothing is given', async () => {
      const s = server();
      const { wrapper } = await boot(s, path);
      await replace(wrapper);
      expect(wrapper.find('dialog[open]').exists()).toBe(false);
      expect(wrapper.findAll('[role=alert]').map((a) => a.text())).toContain('There is nothing to change.');
      await wrapper.get('#channel-header-name').setValue('X-Token');
      await replace(wrapper);
      expect(wrapper.findAll('[role=alert]').map((a) => a.text())).toContain('Give the name and the value of the header, or neither.');
      expect(wrapper.find('dialog[open]').exists()).toBe(false);
      expect(requestsOf(s, 'PATCH')).toHaveLength(0);
    });

    test('keeps what the user typed when the password is wrong, and empties the password', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => failure(403, 'wrong_password') });
      const { wrapper } = await boot(s, path);
      await wrapper.get('#channel-url').setValue(secretUrl);
      await replace(wrapper);
      await enter(wrapper);
      await confirm(wrapper);
      expect(dialog(wrapper).get('[role=alert]').text()).toBe('The password is wrong.');
      expect((wrapper.get('#channel-url').element as HTMLInputElement).value).toBe(secretUrl);
      expect((dialog(wrapper).get('input[type=password]').element as HTMLInputElement).value).toBe('');
    });

    test('says that the URL is not allowed', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => failure(422, 'target_not_allowed') });
      const { wrapper } = await boot(s, path);
      await wrapper.get('#channel-url').setValue(otherUrl);
      await replace(wrapper);
      await enter(wrapper);
      await confirm(wrapper);
      expect(wrapper.find('dialog[open]').exists()).toBe(false);
      expect(wrapper.get('section > [role=alert]').text()).toContain('The URL is not allowed.');
    });

    test('for an account of the identity provider sends no password', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => json(200, alertChannel()) }, 'oidc');
      const { wrapper } = await boot(s, path);
      await wrapper.get('#channel-url').setValue(secretUrl);
      await replace(wrapper);
      await confirm(wrapper);
      expect(requestsOf(s, 'PATCH')[0]?.body).toEqual({ url: secretUrl });
    });

    test('for an account of the identity provider offers to sign in again, and returns to this channel', async () => {
      const assign = vi.spyOn(globalThis.location, 'assign').mockImplementation(() => {});
      const s = server('admin', { [`PATCH ${detail}`]: () => failure(403, 'reauthentication_required') }, 'oidc');
      const { wrapper } = await boot(s, path);
      await wrapper.get('#channel-url').setValue(secretUrl);
      await replace(wrapper);
      await confirm(wrapper);
      await dialog(wrapper).get('.button-primary').trigger('click');
      expect(assign).toHaveBeenCalledExactlyOnceWith(`/api/v1/oidc/reauthenticate?return_to=${encodeURIComponent(path)}`);
    });
  });

  describe('of the type email', () => {
    const mail = emailChannel();
    const mailPath = `/alert-channels/${mail.id}`;
    const one = (extra: Record<string, Handler> = {}) => server('admin', { [`GET /api/v1/alert-channels/${mail.id}`]: () => json(200, mail), ...extra });

    test('starts from the recipients that it has, and has no URL', async () => {
      const { wrapper } = await boot(one(), mailPath);
      expect((wrapper.get('#channel-recipients').element as HTMLTextAreaElement).value).toBe('soc@example.com\nit@example.com');
      expect(wrapper.find('#channel-url').exists()).toBe(false);
    });

    test('replaces the recipients with the password', async () => {
      const s = one({ [`PATCH /api/v1/alert-channels/${mail.id}`]: () => json(200, emailChannel({ recipients: ['ops@example.org'] })) });
      const { wrapper } = await boot(s, mailPath);
      await wrapper.get('#channel-recipients').setValue('ops@example.org');
      await wrapper.findAll('form')[1]!.trigger('submit');
      await flushPromises();
      await enter(wrapper);
      await confirm(wrapper);
      expect(requestsOf(s, 'PATCH').map((r) => r.body)).toEqual([{ recipients: ['ops@example.org'], password: typed }]);
      expect(wrapper.get('dl').text()).toContain('ops@example.org');
    });

    test('says that there is nothing to change when the recipients are the same', async () => {
      const s = one();
      const { wrapper } = await boot(s, mailPath);
      await wrapper.findAll('form')[1]!.trigger('submit');
      await flushPromises();
      expect(wrapper.find('dialog[open]').exists()).toBe(false);
      expect(wrapper.findAll('[role=alert]').map((a) => a.text())).toContain('There is nothing to change.');
    });

    test.each(['soc@example.com nobody', 'soc@example.com SOC@example.com'])('does not ask for recipients that include %j', async (recipients) => {
      const s = one();
      const { wrapper } = await boot(s, mailPath);
      await wrapper.get('#channel-recipients').setValue(recipients);
      await wrapper.findAll('form')[1]!.trigger('submit');
      await flushPromises();
      expect(wrapper.find('dialog[open]').exists()).toBe(false);
      expect(requestsOf(s, 'PATCH')).toHaveLength(0);
    });

    test('does not ask for recipients that are none', async () => {
      const s = one();
      const { wrapper } = await boot(s, mailPath);
      await wrapper.get('#channel-recipients').setValue('nobody');
      await wrapper.findAll('form')[1]!.trigger('submit');
      await flushPromises();
      expect(wrapper.find('dialog[open]').exists()).toBe(false);
      expect(wrapper.text()).toContain('Not an address: nobody.');
    });
  });

  describe('tested', () => {
    beforeEach(() => {
      vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
    });

    const pending = alertDelivery({ status: 'pending', attempts: 0, last_attempt_at: null, last_status_code: null, delivered_at: null });
    const testing = (answers: ReturnType<typeof alertDelivery>[], extra: Record<string, Handler> = {}) => {
      let next = 0;
      return server('admin', {
        [`POST ${detail}/test`]: () => json(202, pending),
        [`GET /api/v1/alert-deliveries/${deliveryId}`]: () => json(200, answers[Math.min(next++, answers.length - 1)]),
        ...extra,
      });
    };
    const deliveryGets = (s: ReturnType<typeof server>) => s.requests.filter((r) => r.url.startsWith('/api/v1/alert-deliveries')).length;

    test('waits for the worker, asks every two seconds, and shows that the test was delivered', async () => {
      const s = testing([pending, alertDelivery()]);
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'Send a test')!.trigger('click');
      await flushPromises();
      expect(requestsOf(s, 'POST').map((r) => r.url)).toEqual([`${detail}/test`]);
      expect(wrapper.text()).toContain('Waiting for the worker.');
      await vi.advanceTimersByTimeAsync(1999);
      expect(deliveryGets(s)).toBe(0);
      await vi.advanceTimersByTimeAsync(1);
      await flushPromises();
      expect(deliveryGets(s)).toBe(1);
      expect(wrapper.text()).toContain('Waiting for the worker.');
      await vi.advanceTimersByTimeAsync(2000);
      await flushPromises();
      expect(wrapper.text()).toContain('The test message was delivered.');
      await vi.advanceTimersByTimeAsync(20_000);
      expect(deliveryGets(s)).toBe(2);
    });

    test('says why a test failed, in words of its own', async () => {
      const s = testing([alertDelivery({ status: 'dead', last_error: 'http_status', last_status_code: 404, delivered_at: null })]);
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'Send a test')!.trigger('click');
      await flushPromises();
      await vi.advanceTimersByTimeAsync(2000);
      await flushPromises();
      expect(wrapper.get('[role=status]').text()).toBe('The test message was not delivered: The receiver refused the message. (status 404)');
    });

    test('says that the test was canceled', async () => {
      const s = testing([alertDelivery({ status: 'canceled', delivered_at: null })]);
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'Send a test')!.trigger('click');
      await flushPromises();
      await vi.advanceTimersByTimeAsync(2000);
      await flushPromises();
      expect(wrapper.text()).toContain('The test was canceled.');
    });

    test('stops after thirty seconds and offers to check again', async () => {
      const s = testing([pending]);
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'Send a test')!.trigger('click');
      await flushPromises();
      await vi.advanceTimersByTimeAsync(60_000);
      await flushPromises();
      expect(deliveryGets(s)).toBe(15);
      expect(wrapper.text()).toContain('The worker has not sent the test yet.');
      await button(wrapper, 'Check again')!.trigger('click');
      await flushPromises();
      expect(deliveryGets(s)).toBe(16);
    });

    test('cannot be sent again while it waits', async () => {
      const s = testing([pending]);
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'Send a test')!.trigger('click');
      await flushPromises();
      expect(button(wrapper, 'Send a test')!.attributes('disabled')).toBeDefined();
    });

    test('says that a test is waiting already', async () => {
      const s = server('admin', { [`POST ${detail}/test`]: () => failure(409, 'test_pending') });
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'Send a test')!.trigger('click');
      await flushPromises();
      expect(wrapper.get('[role=alert]').text()).toBe('A test of this channel is already waiting for the worker.');
      expect(button(wrapper, 'Send a test')!.attributes('disabled')).toBeUndefined();
    });

    test('does not start to ask when the user left the page before the answer to the test', async () => {
      let answer: (response: Response) => void = () => undefined;
      const s = testing([pending], { [`POST ${detail}/test`]: () => new Promise<Response>((resolve) => (answer = resolve)) as never });
      const { wrapper, router } = await boot(s, path);
      await button(wrapper, 'Send a test')!.trigger('click');
      await router.push('/forbidden');
      await arrive(router, 'forbidden');
      answer(json(202, pending));
      await flushPromises();
      await vi.advanceTimersByTimeAsync(60_000);
      expect(deliveryGets(s)).toBe(0);
    });

    test('stops asking when the user leaves the page', async () => {
      const s = testing([pending]);
      const { wrapper, router } = await boot(s, path);
      await button(wrapper, 'Send a test')!.trigger('click');
      await flushPromises();
      await router.push('/forbidden');
      await arrive(router, 'forbidden');
      await vi.advanceTimersByTimeAsync(60_000);
      expect(deliveryGets(s)).toBe(0);
    });

    test('stops asking and says so when the outcome cannot be read', async () => {
      const s = testing([pending], { [`GET /api/v1/alert-deliveries/${deliveryId}`]: () => failure(500, 'internal_error') });
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'Send a test')!.trigger('click');
      await flushPromises();
      await vi.advanceTimersByTimeAsync(10_000);
      await flushPromises();
      expect(deliveryGets(s)).toBe(1);
      expect(wrapper.get('[role=alert]').text()).toBe('Something went wrong on the server.');
    });

    test('does not ask for a password', async () => {
      const s = testing([pending]);
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'Send a test')!.trigger('click');
      await flushPromises();
      expect(wrapper.find('dialog[open]').exists()).toBe(false);
      expect(requestsOf(s, 'POST')[0]?.body).toBeUndefined();
    });
  });

  describe('deleted', () => {
    test('only once it is disabled, and after the user confirms', async () => {
      const s = server('admin', { [`GET ${detail}`]: () => json(200, alertChannel({ enabled: false })), [`DELETE ${detail}`]: noContent });
      const { wrapper, router } = await boot(s, path);
      await button(wrapper, 'Delete channel')!.trigger('click');
      await flushPromises();
      expect(dialog(wrapper).get('h2').text()).toBe('Delete this alert channel?');
      expect(dialog(wrapper).find('input[type=password]').exists()).toBe(false);
      expect(requestsOf(s, 'DELETE')).toHaveLength(0);
      await dialog(wrapper).get('.danger').trigger('click');
      await flushPromises();
      expect(requestsOf(s, 'DELETE')).toHaveLength(1);
      await arrive(router, 'alert-channels');
    });

    test('is not offered while the channel is enabled', async () => {
      const { wrapper } = await boot(server(), path);
      const deleteButton = button(wrapper, 'Delete channel')!;
      expect(deleteButton.attributes('disabled')).toBeDefined();
      expect(wrapper.text()).toContain('Disable the channel before you delete it.');
    });

    test('says so when the server finds the channel enabled', async () => {
      const s = server('admin', { [`GET ${detail}`]: () => json(200, alertChannel({ enabled: false })), [`DELETE ${detail}`]: () => failure(409, 'alert_channel_enabled') });
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'Delete channel')!.trigger('click');
      await flushPromises();
      await dialog(wrapper).get('.danger').trigger('click');
      await flushPromises();
      expect(wrapper.find('dialog[open]').exists()).toBe(false);
      expect(wrapper.get('section > [role=alert]').text()).toBe('Disable the channel before you delete it.');
    });
  });
});

describe('the deliveries of an incident', () => {
  const incidentPath = `/incidents/${incidentId}`;
  const deliveries = `/api/v1/incidents/${incidentId}/deliveries`;

  function viewing(role: Role, list: ReturnType<typeof alertDelivery>[], extra: Record<string, Handler> = {}) {
    return fakeServer({
      'GET /api/v1/session': () => json(200, sessionBody(role)),
      [`GET /api/v1/incidents/${incidentId}`]: () => json(200, incident()),
      [`GET ${deliveries}`]: () => json(200, { deliveries: list }),
      'GET /api/v1/events': () => json(200, { events: [] }),
      'GET /api/v1/scenarios': () => json(200, { scenarios: [] }),
      ...extra,
    });
  }

  const dead = alertDelivery({ status: 'dead', attempts: 10, last_error: 'http_status', last_status_code: 502, delivered_at: null });
  const rows = (wrapper: Wrapper) => wrapper.findAll('.table').at(-1)!.findAll('tbody tr');

  test('shows the channel, the status and the result of each', async () => {
    const waiting = alertDelivery({ id: 'de11be00-2222-4222-8333-944444444444', channel_name: 'SOC', channel_type: 'email', status: 'pending', attempts: 2, next_attempt_at: '2026-10-22T07:05:00Z', last_error: 'smtp_status', last_status_code: 451, delivered_at: null });
    const { wrapper } = await boot(viewing('admin', [alertDelivery(), waiting, dead]), incidentPath);
    const lines = rows(wrapper);
    expect(lines).toHaveLength(3);
    expect(lines[0]?.text()).toContain('SOAR');
    expect(lines[0]?.text()).toContain('Webhook');
    expect(lines[0]?.text()).toContain('Delivered');
    expect(lines[1]?.text()).toContain('Pending');
    expect(lines[1]?.text()).toContain('The mail server refused the mail (status 451)');
    expect(lines[2]?.text()).toContain('Failed');
    expect(lines[2]?.text()).toContain('The receiver refused the message (status 502)');
    expect(lines[2]?.text()).toContain('10');
  });

  test('shows when a delivery was delivered', async () => {
    const { wrapper } = await boot(viewing('admin', [alertDelivery()]), incidentPath);
    expect(rows(wrapper)[0]?.findAll('td')[4]?.get('time').attributes('datetime')).toBe('2026-10-22T07:00:10Z');
  });

  test('shows when a pending delivery is tried next', async () => {
    const waiting = alertDelivery({ status: 'pending', attempts: 0, last_attempt_at: null, last_status_code: null, last_error: null, delivered_at: null, next_attempt_at: '2026-10-22T07:05:00Z' });
    const { wrapper } = await boot(viewing('admin', [waiting]), incidentPath);
    expect(rows(wrapper)[0]?.text()).toContain('Next attempt:');
  });

  test('says so when no channel was enabled', async () => {
    const { wrapper } = await boot(viewing('admin', []), incidentPath);
    expect(wrapper.text()).toContain('No channel was enabled when this incident opened, so no alert was sent.');
  });

  test('says so when the deliveries cannot be loaded', async () => {
    const { wrapper } = await boot(viewing('admin', [], { [`GET ${deliveries}`]: () => failure(500, 'internal_error') }), incidentPath);
    expect(wrapper.text()).toContain('The deliveries could not be loaded. Something went wrong on the server.');
  });

  test('links an administrator to the channel, and shows the name only to others', async () => {
    const admin = await boot(viewing('admin', [alertDelivery()]), incidentPath);
    expect(rows(admin.wrapper)[0]?.get('a').attributes('href')).toBe(path);
    document.body.innerHTML = '';
    const user = await boot(viewing('user', [alertDelivery()]), incidentPath);
    expect(rows(user.wrapper)[0]?.find('a').exists()).toBe(false);
    expect(rows(user.wrapper)[0]?.text()).toContain('SOAR');
  });

  test('shows a channel name that is markup as text', async () => {
    const { wrapper } = await boot(viewing('user', [alertDelivery({ channel_name: '<img src=x onerror=alert(1)>' })]), incidentPath);
    expect(wrapper.find('img[src=x]').exists()).toBe(false);
    expect(rows(wrapper)[0]?.text()).toContain('<img src=x onerror=alert(1)>');
  });

  describe('sent again', () => {
    test('by an administrator, for a failed delivery only, with no password', async () => {
      const s = viewing('admin', [alertDelivery(), dead], {
        [`POST /api/v1/alert-deliveries/${deliveryId}/retry`]: () => json(200, alertDelivery({ status: 'pending', attempts: 0, last_error: null, last_status_code: null, next_attempt_at: '2026-10-22T07:05:00Z', delivered_at: null })),
      });
      const failed = alertDelivery({ ...dead });
      s.on(`GET ${deliveries}`, () => json(200, { deliveries: [failed] }));
      const { wrapper } = await boot(s, incidentPath);
      expect(wrapper.findAll('button').filter((b) => b.text() === 'Send again')).toHaveLength(1);
      await button(wrapper, 'Send again')!.trigger('click');
      await flushPromises();
      expect(requestsOf(s, 'POST').map((r) => [r.url, r.body])).toEqual([[`/api/v1/alert-deliveries/${deliveryId}/retry`, undefined]]);
      expect(rows(wrapper)[0]?.text()).toContain('Pending');
      expect(button(wrapper, 'Send again')).toBeUndefined();
    });

    test('offers nothing for a delivery that is not failed', async () => {
      const { wrapper } = await boot(viewing('admin', [alertDelivery(), alertDelivery({ id: 'de11be00-3333-4222-8333-944444444444', status: 'canceled' })]), incidentPath);
      expect(button(wrapper, 'Send again')).toBeUndefined();
    });

    test('is not offered to a user or a viewer', async () => {
      for (const role of ['user', 'viewer'] as const) {
        const { wrapper } = await boot(viewing(role, [dead]), incidentPath);
        expect(button(wrapper, 'Send again')).toBeUndefined();
        document.body.innerHTML = '';
      }
    });

    test('says so when the delivery is no longer failed', async () => {
      const s = viewing('admin', [dead], { [`POST /api/v1/alert-deliveries/${deliveryId}/retry`]: () => failure(409, 'delivery_not_dead') });
      const { wrapper } = await boot(s, incidentPath);
      await button(wrapper, 'Send again')!.trigger('click');
      await flushPromises();
      expect(wrapper.text()).toContain('Only a failed delivery of an alert can be sent again.');
      expect(rows(wrapper)[0]?.text()).toContain('Failed');
    });
  });
});

describe('the pages in German', () => {
  test('speak German and keep the values as they are', async () => {
    const { wrapper, i18n } = await boot(server(), path);
    i18n.setLocale('de');
    await flushPromises();
    expect(wrapper.text()).toContain('Ziel ersetzen');
    expect(wrapper.text()).toContain('https://soar.example.com');
  });
});
