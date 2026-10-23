// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, test, vi } from 'vitest';
import { ApiError } from '../api/errors';
import { captureFragmentToken } from './fragment';
import { useLinkForm } from './linkForm';

// A token has the form of the real one, and is plainly made up.
const token = `test-token-${'x'.repeat(33)}`;

function form(send: (token: string) => Promise<void>, withToken = true) {
  captureFragmentToken(
    { pathname: '/activate', search: '', hash: withToken ? `#token=${token}` : '' },
    { replaceState: vi.fn(), state: null },
  );
  const wipe = vi.fn();
  return { ...useLinkForm(send, wipe), wipe };
}

describe('useLinkForm', () => {
  test('starts as a form with a token, and as an invalid link without one', () => {
    expect(form(vi.fn()).state.value).toBe('form');
    expect(form(vi.fn(), false).state.value).toBe('invalid');
  });

  test('sends the token, and after the success neither the token nor the form is left', async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    const f = form(send);
    await f.submit(undefined);
    expect(send).toHaveBeenCalledExactlyOnceWith(token);
    expect(f.state.value).toBe('done');
    expect(f.wipe).toHaveBeenCalledOnce();
    // The token is used up: another attempt sends nothing.
    await f.submit(undefined);
    expect(send).toHaveBeenCalledOnce();
  });

  test('ends the use for a token that the server does not know, and wipes the form', async () => {
    const send = vi.fn().mockRejectedValue(new ApiError('not_found', 404));
    const f = form(send);
    await f.submit(undefined);
    expect(f.state.value).toBe('invalid');
    expect(f.wipe).toHaveBeenCalledOnce();
    await f.submit(undefined);
    expect(send).toHaveBeenCalledOnce();
  });

  test.each(['unavailable', 'network', 'server', 'invalid_request', 'cross_origin'] as const)(
    'keeps the form and the token for %s, so that the user can try again',
    async (kind) => {
      const send = vi.fn().mockRejectedValueOnce(new ApiError(kind, 500)).mockResolvedValue(undefined);
      const f = form(send);
      await f.submit(undefined);
      expect(f.state.value).toBe('form');
      expect(f.wipe).not.toHaveBeenCalled();
      expect(f.error.value).toBeTruthy();
      await f.submit(undefined);
      expect(send).toHaveBeenNthCalledWith(2, token);
      expect(f.error.value).toBeUndefined();
    },
  );

  test('sends nothing while the page has a problem with the input', async () => {
    const send = vi.fn();
    const f = form(send);
    await f.submit('The two passwords are not the same.');
    expect(send).not.toHaveBeenCalled();
    expect(f.error.value).toBe('The two passwords are not the same.');
    expect(f.state.value).toBe('form');
  });

  test('is not busy once the request ended', async () => {
    const f = form(vi.fn().mockRejectedValue(new Error('unexpected')));
    await f.submit(undefined);
    expect(f.busy.value).toBe(false);
  });
});
