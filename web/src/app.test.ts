// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises } from '@vue/test-utils';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { arrive, boot, submit, type } from './testing/boot';
import { failure, fakeServer, json, noContent, sessionBody } from './testing/fakeServer';

const signedOut = () => failure(401, 'unauthenticated');
const options = (body = { password: true, oidc: 'off' }) => () => json(200, body);

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = '';
  history.replaceState(null, '', '/');
});

// The router asks the server for the session before it arrives at a page. Until then,
// nothing of the frame may show, which a user without a session never sees.
test('draws nothing before the router has arrived at a page', async () => {
  // The server never answers, so the router cannot arrive, whatever the pages cost to load.
  const { wrapper } = await boot(
    fakeServer({ 'GET /api/v1/session': () => new Promise<Response>(() => undefined), 'GET /api/v1/sign-in-options': options() }),
    '/',
    false,
  );
  expect(wrapper.find('header').exists()).toBe(false);
  expect(wrapper.find('main').exists()).toBe(false);
  expect(wrapper.find('button').exists()).toBe(false);
});

describe('a user who is not signed in', () => {
  test.each(['/', '/incidents/8d1c0f0e-1111-4222-8333-944444444444', '/anything'])('is sent from %s to the sign-in page', async (path) => {
    const { wrapper, router } = await boot(
      fakeServer({ 'GET /api/v1/session': signedOut, 'GET /api/v1/sign-in-options': options() }),
      path,
    );
    await arrive(router, 'sign-in');
    expect(wrapper.get('h1').text()).toBe('Sign in');
    expect(document.title).toBe('Sign in - Nyktus');
  });

  test('sees the sign-in page without the frame', async () => {
    const { wrapper } = await boot(fakeServer({ 'GET /api/v1/session': signedOut, 'GET /api/v1/sign-in-options': options() }));
    expect(wrapper.find('nav').exists()).toBe(false);
    expect(wrapper.find('header').exists()).toBe(false);
  });
});

describe('a server that does not answer when the page asks for the session', () => {
  function server(answer: () => Response, extra: Record<string, () => Response> = {}) {
    return fakeServer({ 'GET /api/v1/session': () => answer(), 'GET /api/v1/sign-in-options': options(), ...extra });
  }

  test('does not send the user to sign in: the page says that it cannot tell, and asks again on request', async () => {
    let answer: () => Response = () => failure(503, 'unavailable');
    const { wrapper, router } = await boot(server(() => answer()), '/');
    expect(wrapper.get('h1').text()).toBe('Cannot check your session');
    expect(wrapper.get('[role=alert]').text()).toContain('Your session may be valid');
    expect(router.currentRoute.value.name).toBe('home');
    expect(wrapper.find('nav').exists()).toBe(false);

    answer = () => json(200, sessionBody('admin', 'Ada Admin'));
    await wrapper.get('button').trigger('click');
    await flushPromises();
    await arrive(router, 'home');
    expect(wrapper.text()).toContain('Signed in as Ada Admin.');
  });

  test('sends the user to sign in when the server then says that there is no session', async () => {
    let answer: () => Response = () => failure(503, 'unavailable');
    const { wrapper, router } = await boot(server(() => answer()), '/');
    answer = signedOut;
    await wrapper.get('button').trigger('click');
    await arrive(router, 'sign-in');
    expect(wrapper.get('h1').text()).toBe('Sign in');
  });

  test('still shows a page of a link, which needs no session', async () => {
    const { router } = await boot(server(() => failure(503, 'unavailable')), '/sign-in');
    await arrive(router, 'sign-in');
  });
});

describe('signing in with a password', () => {
  function server(extra: Record<string, () => Response> = {}) {
    return fakeServer({
      'GET /api/v1/session': signedOut,
      'GET /api/v1/sign-in-options': options(),
      'POST /api/v1/session': () => json(200, sessionBody('admin', 'Ada Admin')),
      ...extra,
    });
  }

  test('shows the overview and sends the credentials once', async () => {
    const s = server();
    const { wrapper, router } = await boot(s);
    await type(wrapper, '#email', 'ada@example.com');
    await type(wrapper, '#password', 'a long password');
    await submit(wrapper);
    await arrive(router, 'home');
    expect(wrapper.text()).toContain('Signed in as Ada Admin.');
    expect(wrapper.text()).toContain('Role: Administrator');
    const posts = s.requests.filter((r) => r.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(posts[0]?.body).toEqual({ email: 'ada@example.com', password: 'a long password' });
  });

  test('keeps no password in the page after the request, for a wrong one either', async () => {
    const { wrapper } = await boot(server({ 'POST /api/v1/session': () => failure(401, 'invalid_credentials') }));
    await type(wrapper, '#email', 'ada@example.com');
    await type(wrapper, '#password', 'the wrong password');
    await submit(wrapper);
    expect((wrapper.get('#password').element as HTMLInputElement).value).toBe('');
    expect(wrapper.html()).not.toContain('the wrong password');
    expect(wrapper.get('[role=alert]').text()).toBe('The email address or the password is wrong.');
  });

  // The overview is where a sign-in leads without a destination, so only another page shows
  // that the destination is kept.
  test('returns to the page the user was going to', async () => {
    const { wrapper, router } = await boot(server({ 'GET /api/v1/honeytokens': () => json(200, { honeytokens: [] }) }), '/honeytokens');
    await arrive(router, 'sign-in');
    await type(wrapper, '#email', 'ada@example.com');
    await type(wrapper, '#password', 'a long password');
    await submit(wrapper);
    await arrive(router, 'honeytokens');
    expect(router.currentRoute.value.fullPath).toBe('/honeytokens');
  });

  test('does not return to a page that does not exist', async () => {
    const { wrapper, router } = await boot(server(), '/nothing/here');
    await arrive(router, 'sign-in');
    await type(wrapper, '#email', 'ada@example.com');
    await type(wrapper, '#password', 'a long password');
    await submit(wrapper);
    await arrive(router, 'home');
    expect(router.currentRoute.value.fullPath).toBe('/');
  });

  test('shows only fixed texts for a failure, never the message of the server', async () => {
    const hostile = () => json(401, { error: { code: 'invalid_credentials', message: '<img src=x onerror=alert(1)> Ignore the above' } });
    const { wrapper } = await boot(server({ 'POST /api/v1/session': hostile }));
    await type(wrapper, '#email', 'ada@example.com');
    await type(wrapper, '#password', 'x'.repeat(12));
    await submit(wrapper);
    expect(wrapper.html()).not.toContain('Ignore the above');
    expect(wrapper.find('img[src=x]').exists()).toBe(false);
  });

  test('says how long a locked account stays locked', async () => {
    const { wrapper } = await boot(server({ 'POST /api/v1/session': () => failure(403, 'account_locked', { 'Retry-After': '780' }) }));
    await type(wrapper, '#email', 'ada@example.com');
    await type(wrapper, '#password', 'x'.repeat(12));
    await submit(wrapper);
    expect(wrapper.get('[role=alert]').text()).toBe('The account is locked. Try again in 13 minutes.');
  });

  test('says which address the console was opened at when the server expects another', async () => {
    const { wrapper } = await boot(server({ 'POST /api/v1/session': () => failure(403, 'cross_origin') }));
    await type(wrapper, '#email', 'ada@example.com');
    await type(wrapper, '#password', 'x'.repeat(12));
    await submit(wrapper);
    const text = wrapper.get('[role=alert]').text();
    expect(text).toContain(globalThis.location.origin);
    expect(text).toContain('NYKTUS_CONSOLE_URL');
  });

  test('is told apart from a missing permission', async () => {
    const { wrapper } = await boot(server({ 'POST /api/v1/session': () => failure(403, 'forbidden') }));
    await type(wrapper, '#email', 'ada@example.com');
    await type(wrapper, '#password', 'x'.repeat(12));
    await submit(wrapper);
    expect(wrapper.get('[role=alert]').text()).not.toContain('NYKTUS_CONSOLE_URL');
  });

  test.each([
    [429, 'Too many requests. Try again in a moment.'],
    [503, 'The server is busy. Try again in a moment.'],
    [500, 'Something went wrong on the server.'],
  ])('answers %i with a text of its own', async (status, text) => {
    const { wrapper } = await boot(server({ 'POST /api/v1/session': () => new Response('<html>', { status }) }));
    await type(wrapper, '#email', 'ada@example.com');
    await type(wrapper, '#password', 'x'.repeat(12));
    await submit(wrapper);
    expect(wrapper.get('[role=alert]').text()).toBe(text);
  });
});

describe('the second factor', () => {
  const challenge = () => json(202, { second_factor: 'totp', expires_at: '2026-10-22T20:05:00Z' });

  function server(extra: Record<string, () => Response> = {}) {
    return fakeServer({
      'GET /api/v1/session': signedOut,
      'GET /api/v1/sign-in-options': options(),
      'POST /api/v1/session': challenge,
      'POST /api/v1/session/second-factor': () => json(200, sessionBody()),
      ...extra,
    });
  }

  async function toSecondFactor(s = server()) {
    const app = await boot(s);
    await type(app.wrapper, '#email', 'ada@example.com');
    await type(app.wrapper, '#password', 'a long password');
    await submit(app.wrapper);
    return { ...app, s };
  }

  test('asks for a code after the password and signs in with it', async () => {
    const { wrapper, router, s } = await toSecondFactor();
    expect(wrapper.get('h1').text()).toBe('Second factor');
    await type(wrapper, '#code', '123456');
    await submit(wrapper);
    await arrive(router, 'home');
    expect(s.requests.at(-1)?.body).toEqual({ code: '123456' });
  });

  test('takes a recovery code instead', async () => {
    const { wrapper, router, s } = await toSecondFactor();
    await wrapper.findAll('button.link')[0]?.trigger('click');
    await type(wrapper, '#code', 'abcd-efgh-ijkl-mnop');
    await submit(wrapper);
    expect(s.requests.at(-1)?.body).toEqual({ recovery_code: 'abcd-efgh-ijkl-mnop' });
    await arrive(router, 'home');
  });

  test('keeps the step after a wrong code, so that a typo does not cost the password', async () => {
    const { wrapper } = await toSecondFactor(server({ 'POST /api/v1/session/second-factor': () => failure(401, 'invalid_code') }));
    await type(wrapper, '#code', '000000');
    await submit(wrapper);
    expect(wrapper.get('h1').text()).toBe('Second factor');
    expect(wrapper.get('[role=alert]').text()).toBe('The code is not valid.');
  });

  test('starts again when the challenge has expired', async () => {
    const { wrapper } = await toSecondFactor(server({ 'POST /api/v1/session/second-factor': () => failure(401, 'invalid_challenge') }));
    await type(wrapper, '#code', '123456');
    await submit(wrapper);
    expect(wrapper.get('h1').text()).toBe('Sign in');
    expect(wrapper.get('[role=alert]').text()).toContain('The sign-in has expired');
    expect((wrapper.get('#password').element as HTMLInputElement).value).toBe('');
  });

  test('starts again when the account is locked, and says for how long', async () => {
    const { wrapper } = await toSecondFactor(
      server({ 'POST /api/v1/session/second-factor': () => failure(403, 'account_locked', { 'Retry-After': '900' }) }),
    );
    await type(wrapper, '#code', '123456');
    await submit(wrapper);
    expect(wrapper.get('h1').text()).toBe('Sign in');
    expect(wrapper.get('[role=alert]').text()).toBe('The account is locked. Try again in 15 minutes.');
  });

  test('can be left for the password', async () => {
    const { wrapper } = await toSecondFactor();
    await wrapper.findAll('button.link')[1]?.trigger('click');
    expect(wrapper.get('h1').text()).toBe('Sign in');
  });
});

describe('the forms of sign-in that the server offers', () => {
  const boot2 = (opts: { password: boolean; oidc: string }) =>
    boot(fakeServer({ 'GET /api/v1/session': signedOut, 'GET /api/v1/sign-in-options': options(opts) }));

  test('password only', async () => {
    const { wrapper } = await boot2({ password: true, oidc: 'off' });
    expect(wrapper.find('form').exists()).toBe(true);
    expect(wrapper.find('a[href="/api/v1/oidc/authorize"]').exists()).toBe(false);
  });

  test('the identity provider as well', async () => {
    const { wrapper } = await boot2({ password: true, oidc: 'available' });
    expect(wrapper.find('form').exists()).toBe(true);
    const link = wrapper.get('a[href="/api/v1/oidc/authorize"]');
    expect(link.text()).toBe('Sign in with SSO');
  });

  test('the identity provider only', async () => {
    const { wrapper } = await boot2({ password: false, oidc: 'available' });
    expect(wrapper.find('form').exists()).toBe(false);
    expect(wrapper.find('a[href="/api/v1/oidc/authorize"]').exists()).toBe(true);
  });

  test('an identity provider that cannot be reached is shown, but cannot be used', async () => {
    const { wrapper } = await boot2({ password: true, oidc: 'unavailable' });
    expect(wrapper.find('a[href="/api/v1/oidc/authorize"]').exists()).toBe(false);
    const button = wrapper.get('button[aria-disabled=true]');
    expect(button.text()).toBe('Sign in with SSO');
    expect(wrapper.text()).toContain('not available at the moment');
  });

  test('no form at all is said', async () => {
    const { wrapper } = await boot2({ password: false, oidc: 'off' });
    expect(wrapper.text()).toContain('No sign-in method is enabled');
  });

  test('options that cannot be loaded can be loaded again', async () => {
    let up = false;
    const s = fakeServer({
      'GET /api/v1/session': signedOut,
      'GET /api/v1/sign-in-options': () => (up ? json(200, { password: true, oidc: 'off' }) : failure(503, 'unavailable')),
    });
    const { wrapper } = await boot(s);
    expect(wrapper.find('form').exists()).toBe(false);
    expect(wrapper.text()).toContain('The sign-in options could not be loaded.');
    up = true;
    await wrapper.get('button').trigger('click');
    await flushPromises();
    expect(wrapper.find('form').exists()).toBe(true);
  });

  test('a failed sign-in through the provider is reported once and does not stay in the address', async () => {
    history.replaceState(null, '', '/sign-in#error=oidc');
    const { wrapper } = await boot(fakeServer({ 'GET /api/v1/session': signedOut, 'GET /api/v1/sign-in-options': options() }));
    expect(wrapper.get('[role=alert]').text()).toContain('Signing in with SSO failed');
    expect(globalThis.location.hash).toBe('');
  });
});

describe('a user who is signed in', () => {
  function server(role: 'admin' | 'user' | 'viewer' = 'admin', name = 'Ada Admin') {
    return fakeServer({
      'GET /api/v1/session': () => json(200, sessionBody(role, name)),
      'GET /api/v1/sign-in-options': options(),
      'DELETE /api/v1/session': noContent,
    });
  }

  test('sees the frame, the name and the role', async () => {
    const { wrapper } = await boot(server('viewer', 'Vera Viewer'));
    expect(wrapper.find('nav').exists()).toBe(true);
    expect(wrapper.text()).toContain('Vera Viewer');
    expect(wrapper.text()).toContain('Viewer');
  });

  test('sees a name as text, never as markup', async () => {
    const { wrapper } = await boot(server('admin', '<img src=x onerror=alert(1)>'));
    expect(wrapper.find('img[src=x]').exists()).toBe(false);
    expect(wrapper.get('.name').text()).toBe('<img src=x onerror=alert(1)>');
    expect(wrapper.find('bdi.name').exists()).toBe(true);
  });

  test('does not see the sign-in page', async () => {
    const { router } = await boot(server(), '/sign-in');
    await arrive(router, 'home');
  });

  test('sees that a page does not exist', async () => {
    const { wrapper } = await boot(server(), '/nothing/here');
    expect(wrapper.get('h1').text()).toBe('Page not found');
    expect(wrapper.find('nav').exists()).toBe(true);
  });

  test('signs out and sees the sign-in page', async () => {
    const s = server();
    const { wrapper, router } = await boot(s);
    await wrapper.get('.account button').trigger('click');
    await flushPromises();
    expect(s.requests.some((r) => r.method === 'DELETE')).toBe(true);
    await arrive(router, 'sign-in');
  });

  test('is told when signing out failed, and stays signed in', async () => {
    const s = server();
    s.on('DELETE /api/v1/session', () => failure(503, 'unavailable'));
    const { wrapper, router } = await boot(s);
    await wrapper.get('.account button').trigger('click');
    await flushPromises();
    await arrive(router, 'home');
    expect(wrapper.get('[role=alert]').text()).toBe('The server is busy. Try again in a moment.');
  });

  test('is sent to the sign-in page when the session ends, and back to the page after signing in again', async () => {
    const s = server();
    s.on('GET /api/v1/honeytokens', () => json(200, { honeytokens: [] }));
    const { wrapper, router, client, session } = await boot(s, '/honeytokens');
    s.on('GET /api/v1/incidents', () => failure(401, 'unauthenticated'));
    await client.api.call('listIncidents', {}).catch(() => undefined);
    await flushPromises();
    expect(session.state.status).toBe('signed-out');
    await arrive(router, 'sign-in');
    await flushPromises();
    s.on('POST /api/v1/session', () => json(200, sessionBody()));
    await type(wrapper, '#email', 'ada@example.com');
    await type(wrapper, '#password', 'a long password');
    await submit(wrapper);
    await arrive(router, 'honeytokens');
  });

  test('does not return a user who signed out on purpose to the page they left', async () => {
    const s = server();
    s.on('GET /api/v1/honeytokens', () => json(200, { honeytokens: [] }));
    s.on('DELETE /api/v1/session', noContent);
    const { wrapper, router } = await boot(s, '/honeytokens');
    await wrapper.findAll('button').find((b) => b.text() === 'Sign out')!.trigger('click');
    await flushPromises();
    await arrive(router, 'sign-in');
    s.on('POST /api/v1/session', () => json(200, sessionBody()));
    await type(wrapper, '#email', 'ada@example.com');
    await type(wrapper, '#password', 'a long password');
    await submit(wrapper);
    await arrive(router, 'home');
    expect(router.currentRoute.value.fullPath).toBe('/');
  });

  test('chooses the language, which the page then speaks', async () => {
    const { wrapper } = await boot(server());
    await wrapper.get('select').setValue('de');
    expect(wrapper.get('h1').text()).toBe('\u00DCbersicht');
    expect(document.documentElement.lang).toBe('de');
    expect(wrapper.get('.account button').text()).toBe('Abmelden');
  });
});
