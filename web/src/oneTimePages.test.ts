// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises } from '@vue/test-utils';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { arrive, boot, submit, type } from './testing/boot';
import { failure, fakeServer, json, sessionBody } from './testing/fakeServer';

// A token has the form of the real one, and is plainly made up.
const token = `test-token-${'x'.repeat(33)}`;
const strongPassword = 'a long and fine password';

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = '';
  history.replaceState(null, '', '/');
});

function open(path: string, hash = `#token=${token}`) {
  history.replaceState(null, '', path + hash);
}

const signedOut = () => failure(401, 'unauthenticated');

const pages = [
  {
    name: 'activation',
    path: '/activate',
    route: 'POST /api/v1/activation',
    title: 'Activate your account',
    done: 'Your account is activated. You can now sign in.',
    submitText: 'Activate account',
  },
  {
    name: 'reset of a password',
    path: '/reset-password',
    route: 'POST /api/v1/password-reset',
    title: 'Choose a new password',
    done: 'Your password has been changed. You can now sign in with it.',
    submitText: 'Change password',
  },
] as const;

describe.each(pages)('the $name page', (page) => {
  function server(extra: Record<string, () => Response> = {}) {
    return fakeServer({
      'GET /api/v1/session': signedOut,
      [page.route]: () => json(200, sessionBody('user', 'Jane')),
      ...extra,
    });
  }

  async function start(s = server(), hash = `#token=${token}`) {
    open(page.path, hash);
    return { s, ...(await boot(s, page.path)) };
  }

  async function fill(wrapper: Awaited<ReturnType<typeof start>>['wrapper'], password = strongPassword, repeat = password) {
    await type(wrapper, '#new-password', password);
    await type(wrapper, '#repeat-password', repeat);
  }

  test('asks for a new password without a session, and sets it with the token in the body', async () => {
    const { s, wrapper } = await start();
    expect(wrapper.get('h1').text()).toBe(page.title);
    expect(wrapper.find('nav').exists()).toBe(false);
    await fill(wrapper);
    await submit(wrapper);
    const post = s.requests.find((r) => r.method === 'POST');
    expect(post?.body).toEqual({ token, password: strongPassword });
    expect(wrapper.get('[role=status]').text()).toBe(page.done);
    expect(wrapper.find('form').exists()).toBe(false);
    expect(wrapper.get('a').attributes('href')).toBe('/sign-in');
  });

  test('takes the token out of the address before the router sees it', async () => {
    const { s, router, wrapper } = await start();
    expect(globalThis.location.hash).toBe('');
    expect(router.currentRoute.value.hash).toBe('');
    expect(router.currentRoute.value.fullPath).toBe(page.path);
    expect(wrapper.html()).not.toContain(token);
    await fill(wrapper);
    await submit(wrapper);
    // The token goes to the server once, in the body, never in an address.
    expect(s.requests.every((r) => !r.url.includes(token))).toBe(true);
    expect(wrapper.html()).not.toContain(token);
  });

  test('does not know the token after a reload, which removed it from the address', async () => {
    await start();
    document.body.innerHTML = '';
    const s = server();
    const { wrapper } = await boot(s, page.path);
    expect(wrapper.find('form').exists()).toBe(false);
    expect(wrapper.get('[role=status]').text()).toContain('This link is invalid');
    expect(s.requests.filter((r) => r.method === 'POST')).toHaveLength(0);
  });

  test.each([['without a token', ''], ['with an empty token', '#token='], ['with a token of the wrong form', '#token=<script>']])(
    'says that the link is not valid %s, and sends nothing',
    async (_, hash) => {
      const { s, wrapper } = await start(server(), hash);
      expect(wrapper.find('form').exists()).toBe(false);
      expect(wrapper.get('[role=status]').text()).toContain('This link is invalid');
      expect(s.requests.filter((r) => r.method === 'POST')).toHaveLength(0);
    },
  );

  test('checks the password before it asks the server', async () => {
    const { s, wrapper } = await start();
    await fill(wrapper, 'too short');
    await submit(wrapper);
    expect(wrapper.get('[role=alert]').text()).toBe('The password needs at least 12 characters.');
    await fill(wrapper, strongPassword, 'another long password');
    await submit(wrapper);
    expect(wrapper.get('[role=alert]').text()).toBe('The two passwords are not the same.');
    await fill(wrapper, 'x'.repeat(129));
    await submit(wrapper);
    expect(wrapper.get('[role=alert]').text()).toBe('The password can have at most 128 characters.');
    expect(s.requests.filter((r) => r.method === 'POST')).toHaveLength(0);
  });

  test('says the same for a token that is unknown, expired or used, and wipes the form', async () => {
    const { wrapper } = await start(server({ [page.route]: () => failure(404, 'not_found') }));
    await fill(wrapper);
    await submit(wrapper);
    expect(wrapper.find('form').exists()).toBe(false);
    expect(wrapper.find('input').exists()).toBe(false);
    expect(wrapper.get('[role=status]').text()).toContain('This link is invalid');
    expect(wrapper.html()).not.toContain(strongPassword);
  });

  test('keeps the form for a failure that the user can try again, and sends the token again', async () => {
    let busy = true;
    const { s, wrapper } = await start(
      server({ [page.route]: () => (busy ? failure(503, 'unavailable') : json(200, sessionBody('user'))) }),
    );
    await fill(wrapper);
    await submit(wrapper);
    expect(wrapper.get('[role=alert]').text()).toBe('The server is busy. Try again in a moment.');
    expect((wrapper.get('#new-password').element as HTMLInputElement).value).toBe(strongPassword);
    busy = false;
    await submit(wrapper);
    expect(wrapper.get('[role=status]').text()).toBe(page.done);
    const posts = s.requests.filter((r) => r.method === 'POST');
    expect(posts.map((r) => (r.body as { token: string }).token)).toEqual([token, token]);
  });

  test('keeps the form when the server finds the input invalid', async () => {
    const { wrapper } = await start(server({ [page.route]: () => failure(400, 'invalid_request') }));
    await fill(wrapper);
    await submit(wrapper);
    expect(wrapper.get('[role=alert]').text()).toBe('The input is not valid.');
    expect(wrapper.find('form').exists()).toBe(true);
  });

  test('says which address it was opened at when the server expects another', async () => {
    const { wrapper } = await start(server({ [page.route]: () => failure(403, 'cross_origin') }));
    await fill(wrapper);
    await submit(wrapper);
    expect(wrapper.get('[role=alert]').text()).toContain(globalThis.location.origin);
  });

  test('uses the token once: after the success there is nothing left to send', async () => {
    const { s, wrapper } = await start();
    await fill(wrapper);
    await submit(wrapper);
    expect(wrapper.find('form').exists()).toBe(false);
    expect(s.requests.filter((r) => r.method === 'POST')).toHaveLength(1);
  });

  test('asks for new passwords, which a password manager can fill', async () => {
    const { wrapper } = await start();
    for (const id of ['#new-password', '#repeat-password']) {
      const input = wrapper.get(id);
      expect(input.attributes('type')).toBe('password');
      expect(input.attributes('autocomplete')).toBe('new-password');
    }
    expect(wrapper.get('button[type=submit]').text()).toBe(page.submitText);
  });

  test('speaks German', async () => {
    const { wrapper, i18n } = await start();
    i18n.setLocale('de');
    await flushPromises();
    expect(wrapper.text()).toContain('Zwischen 12 und 128 Zeichen.');
  });

  test('does not wait for the session, which it does not need', { timeout: 3000 }, async () => {
    open(page.path);
    const { wrapper } = await boot(fakeServer({ 'GET /api/v1/session': () => new Promise<Response>(() => undefined) }), page.path);
    expect(wrapper.get('h1').text()).toBe(page.title);
  });

  test('sends the token once when the form is submitted twice before the answer', async () => {
    let answer: (response: Response) => void = () => undefined;
    const { s, wrapper } = await start(server({ [page.route]: () => new Promise<Response>((resolve) => (answer = resolve)) as never }));
    await fill(wrapper);
    await wrapper.get('form').trigger('submit');
    await wrapper.get('form').trigger('submit');
    answer(json(200, sessionBody('user')));
    await flushPromises();
    expect(s.requests.filter((r) => r.method === 'POST')).toHaveLength(1);
  });

  test('is reachable by a user who is signed in', async () => {
    open(page.path);
    const { router } = await boot(
      fakeServer({ 'GET /api/v1/session': () => json(200, sessionBody()) }),
      page.path,
    );
    await arrive(router, page.path.slice(1));
  });
});

// The router reads the address when it is created, and must find no token in it. Only the
// real history of the browser does that, so this test does not use the memory history.
test('the router never holds the token, which the real history would otherwise give it', async () => {
  vi.resetModules();
  vi.stubGlobal('fetch', fakeServer({ 'GET /api/v1/session': signedOut }).fetch);
  open('/activate');
  const { createConsole } = await import('./app');
  const { app, router } = createConsole();
  const root = document.createElement('div');
  document.body.append(root);
  app.mount(root);
  await router.isReady();
  await vi.waitFor(() => expect(router.currentRoute.value.name).toBe('activate'));
  expect(router.currentRoute.value.hash).toBe('');
  expect(router.currentRoute.value.fullPath).toBe('/activate');
  expect(globalThis.location.href).not.toContain(token);
  expect(root.innerHTML).not.toContain(token);
  app.unmount();
});

describe('the setup page', () => {
  function server(extra: Record<string, () => Response> = {}) {
    return fakeServer({
      'GET /api/v1/session': signedOut,
      'POST /api/v1/setup': () => json(201, sessionBody('admin', 'Ada').user),
      ...extra,
    });
  }

  async function start(s = server()) {
    open('/setup');
    return { s, ...(await boot(s, '/setup')) };
  }

  async function fill(wrapper: Awaited<ReturnType<typeof start>>['wrapper']) {
    await type(wrapper, '#email', 'ada@example.com');
    await type(wrapper, '#display-name', '  Ada Admin  ');
    await type(wrapper, '#new-password', strongPassword);
    await type(wrapper, '#repeat-password', strongPassword);
  }

  test('creates the first administrator with the token in the body', async () => {
    const { s, wrapper } = await start();
    expect(wrapper.get('h1').text()).toBe('Set up Nyktus');
    await fill(wrapper);
    await submit(wrapper);
    const post = s.requests.find((r) => r.method === 'POST');
    expect(post?.url).toBe('/api/v1/setup');
    expect(post?.body).toEqual({ token, email: 'ada@example.com', display_name: 'Ada Admin', password: strongPassword });
    expect(wrapper.get('[role=status]').text()).toBe('The administrator has been created. You can sign in now.');
    expect(wrapper.find('input').exists()).toBe(false);
  });

  test('asks for a name that is more than spaces, before it asks the server', async () => {
    const { s, wrapper } = await start();
    await fill(wrapper);
    await type(wrapper, '#display-name', '   ');
    await submit(wrapper);
    expect(wrapper.get('[role=alert]').text()).toBe('Enter a name.');
    expect(s.requests.filter((r) => r.method === 'POST')).toHaveLength(0);
  });

  test('says nothing about why a setup link does not work', async () => {
    const { wrapper } = await start(server({ 'POST /api/v1/setup': () => failure(404, 'not_found') }));
    await fill(wrapper);
    await submit(wrapper);
    expect(wrapper.get('[role=status]').text()).toContain('This setup link is invalid.');
    expect(wrapper.html()).not.toContain('ada@example.com');
  });

  test('shows the page to a visitor with a link that has no token as invalid, never as a form', async () => {
    history.replaceState(null, '', '/setup');
    const s = server();
    const { wrapper } = await boot(s, '/setup');
    expect(wrapper.find('form').exists()).toBe(false);
    expect(s.requests.filter((r) => r.method === 'POST')).toHaveLength(0);
  });
});
