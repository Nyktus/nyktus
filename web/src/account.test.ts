// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises } from '@vue/test-utils';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type { Handler } from './testing/fakeServer';
import { boot } from './testing/boot';
import { failure, fakeServer, json, noContent, sessionBody } from './testing/fakeServer';

beforeEach(() => {
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

type Wrapper = Awaited<ReturnType<typeof boot>>['wrapper'];

// Plainly made up, so that a scan for secrets does not take them for real ones.
const typed = 'test-password-not-real';
const next = 'test-new-password-not-real';
const secret = 'TESTTESTTESTTEST';
const uri = `otpauth://totp/Nyktus:ada@example.com?secret=${secret}&issuer=Nyktus`;
const codes = Array.from({ length: 10 }, (_, i) => `test-code-${String(i).padStart(2, '0')}-aaaa`);
const setupBody = (expires = '2026-10-23T17:40:00Z') => ({ secret, uri, expires_at: expires });

function server(totp = false, method: 'password' | 'oidc' = 'password', extra: Record<string, Handler> = {}) {
  return fakeServer({
    'GET /api/v1/session': () => json(200, sessionBody('admin', 'Ada Admin', method, totp)),
    ...extra,
  });
}

const requestsOf = (s: ReturnType<typeof server>, method: string) => s.requests.filter((r) => r.method === method);
// A button of the page, not one of its dialogs, which are always in the page and may carry the same text.
const button = (wrapper: Wrapper, label: string) => wrapper.findAll('button').find((b) => b.text() === label && b.element.closest('dialog') === null);
const dialog = (wrapper: Wrapper) => wrapper.get('dialog[open]');
/** What the page holds in its state, which the page does not show: a secret must not stay in it either. */
const state = (wrapper: Wrapper) => wrapper.findComponent({ name: 'AccountView' }).vm as unknown as { setup: unknown; setupExpired: boolean; codes: unknown };

/** Every place that scripts or the browser keep, apart from the page itself. */
function elsewhere(s: ReturnType<typeof server>, router: { currentRoute: { value: unknown } }, skip: (r: { method: string }) => boolean = () => false): string {
  return JSON.stringify([
    globalThis.location.href,
    history.state,
    router.currentRoute.value,
    Object.entries(localStorage),
    Object.entries(sessionStorage),
    document.cookie,
    s.requests.map((r) => r.url),
    s.requests.filter((r) => !skip(r)).map((r) => r.body),
  ]);
}

describe('the account', () => {
  test('shows who is signed in', async () => {
    const { wrapper } = await boot(server(), '/account');
    expect(wrapper.get('h1').text()).toBe('Your account');
    expect(wrapper.get('.lede').text()).toContain('Ada Admin');
    expect(wrapper.get('.lede').text()).toContain('ada@example.com');
  });

  test('is reached through the name in the frame, for every role', async () => {
    for (const role of ['admin', 'user', 'viewer'] as const) {
      const s = fakeServer({ 'GET /api/v1/session': () => json(200, sessionBody(role)) });
      const { wrapper } = await boot(s, '/');
      expect(wrapper.get('a.who').attributes('href')).toBe('/account');
      await wrapper.get('a.who').trigger('click');
      await flushPromises();
      document.body.innerHTML = '';
    }
  });

  test('asks the server for the state of the factor, not the copy from the sign-in', async () => {
    const s = server(true);
    const { wrapper } = await boot(s, '/account');
    expect(s.requests.filter((r) => r.url === '/api/v1/session').length).toBeGreaterThanOrEqual(2);
    expect(wrapper.text()).toContain('MFA is on');
  });

  test('offers nothing to an account of the identity provider, and says where to change it', async () => {
    const { wrapper } = await boot(server(false, 'oidc'), '/account');
    expect(wrapper.text()).toContain('managed by an identity provider');
    expect(wrapper.find('form').exists()).toBe(false);
    expect(wrapper.find('input[type=password]').exists()).toBe(false);
    expect(button(wrapper, 'Set up a second factor')).toBeUndefined();
  });

  test('says so when the account cannot be loaded', async () => {
    let asked = 0;
    const s = fakeServer({ 'GET /api/v1/session': () => (++asked === 1 ? json(200, sessionBody()) : failure(500, 'internal_error')) });
    const { wrapper } = await boot(s, '/account');
    expect(wrapper.get('[role=alert]').text()).toBe('Something went wrong on the server.');
    expect(wrapper.find('form').exists()).toBe(false);
  });
});

describe('the password', () => {
  const route = 'PUT /api/v1/session/password';
  const fill = async (wrapper: Wrapper, overrides: Record<string, string> = {}) => {
    const values = { '#current-password': typed, '#new-password': next, '#repeat-password': next, ...overrides };
    for (const [selector, value] of Object.entries(values)) {
      await wrapper.get(selector).setValue(value);
    }
    await wrapper.findAll('form')[0]!.trigger('submit');
    await flushPromises();
  };
  const fields = (wrapper: Wrapper) => ['#current-password', '#new-password', '#repeat-password'].map((id) => (wrapper.get(id).element as HTMLInputElement).value);

  test('is changed with the current one and the new one', async () => {
    const s = server(false, 'password', { [route]: noContent });
    const { wrapper } = await boot(s, '/account');
    await fill(wrapper);
    expect(requestsOf(s, 'PUT').map((r) => r.body)).toEqual([{ current_password: typed, new_password: next }]);
    expect(wrapper.get('[role=status]').text()).toBe('The password has been changed. Your other sessions have ended.');
  });

  test('is gone from the fields once the request is answered, and is kept nowhere', async () => {
    const s = server(false, 'password', { [route]: noContent });
    const { wrapper, router } = await boot(s, '/account');
    await fill(wrapper);
    expect(fields(wrapper)).toEqual(['', '', '']);
    for (const value of [typed, next]) {
      expect(wrapper.html()).not.toContain(value);
      expect(elsewhere(s, router, (r) => r.method === 'PUT')).not.toContain(value);
    }
  });

  test('is gone from the fields also when the server refuses', async () => {
    const s = server(false, 'password', { [route]: () => failure(403, 'wrong_password') });
    const { wrapper } = await boot(s, '/account');
    await fill(wrapper);
    expect(fields(wrapper)).toEqual(['', '', '']);
    expect(wrapper.get('[role=alert]').text()).toBe('The current password is wrong. A wrong password counts as a failed sign-in.');
    expect(wrapper.find('[role=status]').exists()).toBe(false);
  });

  test('says how long the account is locked', async () => {
    const s = server(false, 'password', { [route]: () => failure(403, 'account_locked', { 'Retry-After': '900' }) });
    const { wrapper } = await boot(s, '/account');
    await fill(wrapper);
    expect(wrapper.get('[role=alert]').text()).toBe('The account is locked. Try again in 15 minutes.');
  });

  test.each([
    ['too short', { '#new-password': 'short', '#repeat-password': 'short' }, 'The password needs at least 12 characters.'],
    ['different', { '#repeat-password': `${next}x` }, 'The two passwords are not the same.'],
    ['too long', { '#new-password': 'x'.repeat(129), '#repeat-password': 'x'.repeat(129) }, 'The password can have at most 128 characters.'],
  ])('is not sent when the new one is %s', async (_, overrides, text) => {
    const s = server(false, 'password', { [route]: noContent });
    const { wrapper } = await boot(s, '/account');
    await fill(wrapper, overrides);
    expect(requestsOf(s, 'PUT')).toHaveLength(0);
    expect(wrapper.get('[role=alert]').text()).toBe(text);
  });

  test('does not show a success after a failure, nor a failure after a success', async () => {
    let fail = true;
    const s = server(false, 'password', { [route]: () => (fail ? failure(500, 'internal_error') : noContent()) });
    const { wrapper } = await boot(s, '/account');
    await fill(wrapper);
    expect(wrapper.find('[role=status]').exists()).toBe(false);
    fail = false;
    await fill(wrapper);
    expect(wrapper.find('[role=alert]').exists()).toBe(false);
    expect(wrapper.get('[role=status]').text()).toContain('has been changed');
  });
});

describe('the second factor', () => {
  const setupRoute = 'POST /api/v1/session/totp';
  const confirmRoute = 'POST /api/v1/session/totp/confirmation';

  async function begin(s: ReturnType<typeof server>) {
    const app = await boot(s, '/account');
    await button(app.wrapper, 'Set up a second factor')!.trigger('click');
    await flushPromises();
    await dialog(app.wrapper).get('input[type=password]').setValue(typed);
    await dialog(app.wrapper).get('.button-primary').trigger('click');
    await flushPromises();
    return app;
  }

  const enter = async (wrapper: Wrapper, code: string) => {
    await wrapper.get('#setup-code').setValue(code);
    await wrapper.get('#setup-code').element.closest('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
    await flushPromises();
  };

  describe('set up', () => {
    const one = (extra: Record<string, Handler> = {}) => server(false, 'password', { [setupRoute]: () => json(201, setupBody(), { 'Cache-Control': 'no-store' }), ...extra });

    test('asks for the password first, and sends nothing before it', async () => {
      const s = one();
      const { wrapper } = await boot(s, '/account');
      await button(wrapper, 'Set up a second factor')!.trigger('click');
      await flushPromises();
      expect(dialog(wrapper).get('h2').text()).toBe('Set up a second factor');
      expect(requestsOf(s, 'POST')).toHaveLength(0);
    });

    // A password manager files a password under an account, so the form of the dialog names it.
    test('names the account in the form of the password, for a password manager', async () => {
      const { wrapper } = await boot(one(), '/account');
      await button(wrapper, 'Set up a second factor')!.trigger('click');
      await flushPromises();
      const form = dialog(wrapper).get('form');
      expect(form.get('input[autocomplete=username]').element.getAttribute('value')).toBe('ada@example.com');
      expect(form.get('input[type=password]').attributes('autocomplete')).toBe('current-password');
      // Without a submit button, Enter in the password field does nothing once the form has the second text field.
      expect(form.find('button[type=submit]').exists()).toBe(true);
    });

    test('shows the code to scan, the key as text and until when it is valid', async () => {
      const s = one();
      const { wrapper } = await begin(s);
      expect(requestsOf(s, 'POST').map((r) => r.body)).toEqual([{ password: typed }]);
      expect(wrapper.get('svg.qr').attributes('aria-label')).toBe('QR code for the authenticator app');
      expect(wrapper.get('.setup dl').text()).toContain('TEST TEST TEST TEST');
      expect(wrapper.get('.setup time').attributes('datetime')).toBe('2026-10-23T17:40:00Z');
      expect(wrapper.find('dialog[open]').exists()).toBe(false);
    });

    test('keeps the key nowhere but the page', async () => {
      const s = one();
      const { router, wrapper } = await begin(s);
      expect(elsewhere(s, router, (r) => r.method !== 'POST')).not.toContain(secret);
      expect(wrapper.html()).not.toContain(typed);
      expect(wrapper.text()).toContain('TEST TEST TEST TEST');
    });

    test('says so in the dialog when the password is wrong', async () => {
      const { wrapper } = await begin(one({ [setupRoute]: () => failure(403, 'wrong_password') }));
      expect(dialog(wrapper).get('[role=alert]').text()).toBe('The password is wrong.');
      expect(wrapper.find('svg.qr').exists()).toBe(false);
    });

    test('says so when the account has a factor already, and shows that the factor is on', async () => {
      const { wrapper } = await begin(one({ [setupRoute]: () => failure(409, 'totp_enabled') }));
      expect(wrapper.find('dialog[open]').exists()).toBe(false);
      expect(wrapper.get('[role=alert]').text()).toBe('This account has a second factor already.');
      expect(button(wrapper, 'Set up a second factor')).toBeUndefined();
      expect(button(wrapper, 'Turn off MFA')).toBeDefined();
    });

    describe('confirmed', () => {
      const confirming = (extra: Record<string, Handler> = {}) => one({ [confirmRoute]: () => json(200, { recovery_codes: codes }, { 'Cache-Control': 'no-store' }), ...extra });

      test('with the code of the app, spaces ignored, and the factor is on', async () => {
        const s = confirming();
        const { wrapper } = await begin(s);
        await enter(wrapper, '123 456');
        expect(requestsOf(s, 'POST').at(-1)?.body).toEqual({ code: '123456' });
        expect(wrapper.text()).toContain('MFA is on');
        expect(wrapper.find('svg.qr').exists()).toBe(false);
        expect(wrapper.html()).not.toContain(secret);
      });

      test('and the page no longer holds the key, which it only needed to show', async () => {
        const { wrapper } = await begin(confirming());
        expect(state(wrapper).setup).toBeDefined();
        await enter(wrapper, '123456');
        expect(state(wrapper).setup).toBeUndefined();
      });

      test('and then shows the recovery codes once', async () => {
        const { wrapper } = await begin(confirming());
        await enter(wrapper, '123456');
        const region = wrapper.get('[role=region]');
        expect(region.findAll('li').map((li) => li.text())).toEqual(codes);
      });

      test('lets the field take a code that is pasted with its separators', async () => {
        const { wrapper } = await begin(confirming());
        expect(Number(wrapper.get('#setup-code').attributes('maxlength'))).toBeGreaterThanOrEqual(12);
      });

      test('sends no code that is not six digits', async () => {
        const s = confirming();
        const { wrapper } = await begin(s);
        for (const code of ['', '12345', '1234567', 'abcdef']) {
          await enter(wrapper, code);
        }
        expect(requestsOf(s, 'POST').filter((r) => r.url.endsWith('/confirmation'))).toHaveLength(0);
        expect(wrapper.get('form [role=alert]').text()).toBe('The code has six digits.');
      });

      test('keeps the setup and empties the field when the code is wrong', async () => {
        const { wrapper } = await begin(confirming({ [confirmRoute]: () => failure(403, 'wrong_code') }));
        await enter(wrapper, '123456');
        expect(wrapper.get('form [role=alert]').text()).toBe('The code is wrong. Try the next one that the app shows.');
        expect((wrapper.get('#setup-code').element as HTMLInputElement).value).toBe('');
        expect(wrapper.find('svg.qr').exists()).toBe(true);
      });

      test('says that the setup expired, when the server says so, and offers to start again', async () => {
        const { wrapper } = await begin(confirming({ [confirmRoute]: () => failure(409, 'no_totp_setup') }));
        await enter(wrapper, '123456');
        expect(wrapper.get('[role=alert]').text()).toBe('The setup has expired. Start again.');
        expect(wrapper.find('svg.qr').exists()).toBe(false);
        expect(wrapper.html()).not.toContain(secret);
        expect(button(wrapper, 'Start again')).toBeDefined();
      });

      // Only the server knows when the setup ends; a clock of the browser that runs ahead of it
      // would otherwise make the setup impossible.
      test('asks the server even when the clock of the browser says that the time is over', async () => {
        const s = confirming();
        const { wrapper } = await begin(s);
        vi.setSystemTime(new Date('2026-10-23T17:40:01Z'));
        await enter(wrapper, '123456');
        expect(requestsOf(s, 'POST').filter((r) => r.url.endsWith('/confirmation'))).toHaveLength(1);
        expect(wrapper.find('[role=alert]').exists()).toBe(false);
        expect(wrapper.text()).toContain('MFA is on');
      });

      test('takes a code that the app shows with spaces or hyphens', async () => {
        const s = confirming();
        const { wrapper } = await begin(s);
        await enter(wrapper, '123-456');
        expect(requestsOf(s, 'POST').filter((r) => r.url.endsWith('/confirmation')).map((r) => r.body)).toEqual([{ code: '123456' }]);
      });

      test('shows another key when the user starts again', async () => {
        let answer = secret;
        const s = confirming({ [setupRoute]: () => json(201, { ...setupBody(), secret: answer }), [confirmRoute]: () => failure(409, 'no_totp_setup') });
        const { wrapper } = await begin(s);
        await enter(wrapper, '123456');
        answer = 'OTHEROTHEROTHERX';
        await button(wrapper, 'Start again')!.trigger('click');
        await flushPromises();
        await dialog(wrapper).get('input[type=password]').setValue(typed);
        await dialog(wrapper).get('.button-primary').trigger('click');
        await flushPromises();
        expect(wrapper.text()).toContain('OTHE ROTH EROT HERX');
        expect(wrapper.text()).not.toContain('TEST TEST');
        expect(wrapper.find('[role=alert]').exists()).toBe(false);
        expect(state(wrapper).setupExpired).toBe(false);
      });
    });
  });

  describe('the recovery codes', () => {
    const shown = async () => {
      const s = server(false, 'password', { [setupRoute]: () => json(201, setupBody()), [confirmRoute]: () => json(200, { recovery_codes: codes }) });
      const app = await begin(s);
      await enter(app.wrapper, '123456');
      return { ...app, s };
    };

    test('are gone once the user says that they saved them', async () => {
      const { wrapper } = await shown();
      await wrapper.get('[role=region] button.button-primary').trigger('click');
      expect(wrapper.find('[role=region]').exists()).toBe(false);
      expect(wrapper.html()).not.toContain(codes[0]);
    });

    test('are gone when the user leaves, and the page that they come back to does not have them', async () => {
      const { wrapper, router } = await shown();
      await router.push('/');
      await flushPromises();
      await router.push('/account');
      await flushPromises();
      expect(wrapper.html()).not.toContain(codes[0]);
    });

    test('are kept nowhere', async () => {
      const { s, router, wrapper } = await shown();
      expect(elsewhere(s, router, (r) => r.method !== 'POST')).not.toContain(codes[0]);
      expect(wrapper.html()).toContain(codes[0]);
    });

    test('are copied as lines', async () => {
      const writeText = vi.fn().mockResolvedValue(undefined);
      vi.stubGlobal('navigator', { ...globalThis.navigator, clipboard: { writeText } });
      const { wrapper } = await shown();
      await wrapper.get('[role=region] button.small').trigger('click');
      expect(writeText).toHaveBeenCalledExactlyOnceWith(`${codes.join('\n')}\n`);
    });

    test('are saved as a text file, which is never opened', async () => {
      const blobs: Blob[] = [];
      const create = vi.fn((blob: Blob) => {
        blobs.push(blob);
        return 'blob:test';
      });
      vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: create, revokeObjectURL: vi.fn() }));
      const names: string[] = [];
      const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
        names.push(this.download);
      });
      const { wrapper } = await shown();
      const save = wrapper.findAll('[role=region] button').find((b) => b.text() === 'Download as text')!;
      await save.trigger('click');
      expect(click).toHaveBeenCalledOnce();
      expect(await blobs[0]!.text()).toBe(`${codes.join('\n')}\n`);
      expect(blobs[0]!.type).toBe('text/plain');
      expect(names).toEqual(['nyktus-recovery-codes.txt']);
    });
  });

  describe('with a factor that is on', () => {
    const replaceRoute = 'POST /api/v1/session/totp/recovery-codes';
    const removeRoute = 'DELETE /api/v1/session/totp';
    const on = (extra: Record<string, Handler> = {}) => server(true, 'password', extra);

    async function open(s: ReturnType<typeof server>, label: string) {
      const app = await boot(s, '/account');
      await button(app.wrapper, label)!.trigger('click');
      await flushPromises();
      return app;
    }

    const confirm = async (wrapper: Wrapper, code: string) => {
      await dialog(wrapper).get('input[type=password]').setValue(typed);
      await dialog(wrapper).get('input[autocomplete=one-time-code]').setValue(code);
      await dialog(wrapper).get('.button-primary').trigger('click');
      await flushPromises();
    };

    test('offers no setup, but replacing the codes and removing the factor', async () => {
      const { wrapper } = await boot(on(), '/account');
      expect(button(wrapper, 'Set up a second factor')).toBeUndefined();
      expect(button(wrapper, 'Replace the recovery codes')).toBeDefined();
      expect(button(wrapper, 'Turn off MFA')).toBeDefined();
    });

    describe('replacing the recovery codes', () => {
      test('asks for the password and a code, and sends nothing before them', async () => {
        const s = on();
        const { wrapper } = await open(s, 'Replace the recovery codes');
        expect(dialog(wrapper).get('h2').text()).toBe('Replace the recovery codes?');
        expect(dialog(wrapper).find('input[type=password]').exists()).toBe(true);
        expect(dialog(wrapper).find('input[autocomplete=one-time-code]').exists()).toBe(true);
        expect(requestsOf(s, 'POST')).toHaveLength(0);
      });

      test('sends the password with a code of the app, and shows the new codes', async () => {
        const s = on({ [replaceRoute]: () => json(200, { recovery_codes: codes }) });
        const { wrapper } = await open(s, 'Replace the recovery codes');
        expect(state(wrapper).codes).toBeUndefined();
        await confirm(wrapper, '123 456');
        expect(requestsOf(s, 'POST').map((r) => r.body)).toEqual([{ password: typed, code: '123456' }]);
        expect(wrapper.get('[role=region]').findAll('li')).toHaveLength(10);
        expect(wrapper.find('dialog[open]').exists()).toBe(false);
      });

      test('sends a recovery code as one, not as a code of the app', async () => {
        const s = on({ [replaceRoute]: () => json(200, { recovery_codes: codes }) });
        const { wrapper } = await open(s, 'Replace the recovery codes');
        await confirm(wrapper, ' test-code-00-aaaa ');
        expect(requestsOf(s, 'POST').map((r) => r.body)).toEqual([{ password: typed, recovery_code: 'test-code-00-aaaa' }]);
      });

      test('says so in the dialog when the code is wrong, and empties the fields', async () => {
        const s = on({ [replaceRoute]: () => failure(403, 'wrong_code') });
        const { wrapper } = await open(s, 'Replace the recovery codes');
        await confirm(wrapper, '123456');
        expect(dialog(wrapper).get('[role=alert]').text()).toBe('The code is wrong.');
        expect((dialog(wrapper).get('input[type=password]').element as HTMLInputElement).value).toBe('');
        expect((dialog(wrapper).get('input[autocomplete=one-time-code]').element as HTMLInputElement).value).toBe('');
        expect(wrapper.find('[role=region]').exists()).toBe(false);
      });

      test('says so in the dialog when the password is wrong', async () => {
        const s = on({ [replaceRoute]: () => failure(403, 'wrong_password') });
        const { wrapper } = await open(s, 'Replace the recovery codes');
        await confirm(wrapper, '123456');
        expect(dialog(wrapper).get('[role=alert]').text()).toBe('The password is wrong.');
      });

      test('forgets a code that was typed and not sent, when the dialog is closed', async () => {
        const s = on();
        const { wrapper } = await open(s, 'Replace the recovery codes');
        await dialog(wrapper).get('input[autocomplete=one-time-code]').setValue('123456');
        await dialog(wrapper).get('.button-ghost').trigger('click');
        await flushPromises();
        await button(wrapper, 'Replace the recovery codes')!.trigger('click');
        await flushPromises();
        expect((dialog(wrapper).get('input[autocomplete=one-time-code]').element as HTMLInputElement).value).toBe('');
        expect(requestsOf(s, 'POST')).toHaveLength(0);
      });

      test('takes a code with a hyphen as the code of the app, and leaves an earlier refusal behind', async () => {
        let refuse = true;
        const s = on({ [replaceRoute]: () => (refuse ? failure(500, 'internal_error') : json(200, { recovery_codes: codes })) });
        const { wrapper } = await open(s, 'Replace the recovery codes');
        await confirm(wrapper, '654321');
        expect(wrapper.get('[role=alert]').text()).toBe('Something went wrong on the server.');
        refuse = false;
        await button(wrapper, 'Replace the recovery codes')!.trigger('click');
        await flushPromises();
        await confirm(wrapper, '654-321');
        expect(requestsOf(s, 'POST').at(-1)?.body).toEqual({ password: typed, code: '654321' });
        expect(wrapper.find('[role=alert]').exists()).toBe(false);
      });

      test('is not sent without a code', async () => {
        const s = on();
        const { wrapper } = await open(s, 'Replace the recovery codes');
        await dialog(wrapper).get('input[type=password]').setValue(typed);
        await dialog(wrapper).get('.button-primary').trigger('click');
        await flushPromises();
        expect(dialog(wrapper).get('[role=alert]').text()).toBe('The code is wrong.');
        expect(requestsOf(s, 'POST')).toHaveLength(0);
      });
    });

    describe('removing the factor', () => {
      test('sends the password and a code, and the account has no factor afterwards', async () => {
        const s = on({ [removeRoute]: noContent });
        const { wrapper } = await open(s, 'Turn off MFA');
        await confirm(wrapper, '654321');
        expect(requestsOf(s, 'DELETE').map((r) => r.body)).toEqual([{ password: typed, code: '654321' }]);
        expect(button(wrapper, 'Set up a second factor')).toBeDefined();
        expect(button(wrapper, 'Turn off MFA')).toBeUndefined();
      });

      test('says so in the dialog when the code is wrong, and keeps the factor', async () => {
        const s = on({ [removeRoute]: () => failure(403, 'wrong_code') });
        const { wrapper } = await open(s, 'Turn off MFA');
        await confirm(wrapper, '654321');
        expect(dialog(wrapper).get('[role=alert]').text()).toBe('The code is wrong.');
        expect(wrapper.text()).toContain('MFA is on');
      });

      test('says so when the account has no factor any more, and offers to set one up', async () => {
        const s = on({ [removeRoute]: () => failure(409, 'totp_not_enabled') });
        const { wrapper } = await open(s, 'Turn off MFA');
        await confirm(wrapper, '654321');
        expect(wrapper.find('dialog[open]').exists()).toBe(false);
        expect(wrapper.get('[role=alert]').text()).toBe('This account has no second factor.');
        expect(button(wrapper, 'Set up a second factor')).toBeDefined();
        expect(button(wrapper, 'Turn off MFA')).toBeUndefined();
      });

      test('forgets the code that was typed when the password is wrong, and says so', async () => {
        const s = on({ [removeRoute]: () => failure(403, 'wrong_password') });
        const { wrapper } = await open(s, 'Turn off MFA');
        await confirm(wrapper, '654321');
        expect(dialog(wrapper).get('[role=alert]').text()).toBe('The password is wrong.');
        expect((dialog(wrapper).get('input[autocomplete=one-time-code]').element as HTMLInputElement).value).toBe('');
        expect((dialog(wrapper).get('input[type=password]').element as HTMLInputElement).value).toBe('');
      });

      test('takes the recovery codes that were shown away with the factor', async () => {
        const s = on({ [replaceRoute]: () => json(200, { recovery_codes: codes }), [removeRoute]: noContent });
        const { wrapper } = await open(s, 'Replace the recovery codes');
        await confirm(wrapper, '654321');
        expect(wrapper.find('[role=region]').exists()).toBe(true);
        await button(wrapper, 'Turn off MFA')!.trigger('click');
        await flushPromises();
        await confirm(wrapper, '654321');
        expect(wrapper.find('[role=region]').exists()).toBe(false);
        expect(state(wrapper).codes).toBeUndefined();
      });

      test('leaves no earlier refusal on the page once it went through', async () => {
        let refuse = true;
        const s = on({ [removeRoute]: () => (refuse ? failure(500, 'internal_error') : noContent()) });
        const { wrapper } = await open(s, 'Turn off MFA');
        await confirm(wrapper, '654321');
        expect(wrapper.get('[role=alert]').text()).toBe('Something went wrong on the server.');
        refuse = false;
        await button(wrapper, 'Turn off MFA')!.trigger('click');
        await flushPromises();
        await confirm(wrapper, '654321');
        expect(wrapper.find('[role=alert]').exists()).toBe(false);
      });

      test('keeps neither the password nor the code', async () => {
        const s = on({ [removeRoute]: noContent });
        const { wrapper, router } = await open(s, 'Turn off MFA');
        await confirm(wrapper, '654321');
        expect(wrapper.html()).not.toContain(typed);
        expect(elsewhere(s, router, (r) => r.method === 'DELETE')).not.toContain('654321');
        for (const input of document.querySelectorAll('input')) {
          expect((input as HTMLInputElement).value).not.toBe('654321');
          expect((input as HTMLInputElement).value).not.toBe(typed);
        }
      });
    });
  });
});

describe('the page in German', () => {
  test('speaks German and keeps the values as they are', async () => {
    const { wrapper, i18n } = await boot(server(), '/account');
    i18n.setLocale('de');
    await flushPromises();
    expect(wrapper.text()).toContain('Zweiten Faktor einrichten');
    expect(wrapper.text()).toContain('ada@example.com');
  });
});
