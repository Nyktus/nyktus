// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, test, vi } from 'vitest';
import { captureFragmentToken, takeFragmentToken } from './fragment';

// A token has the form of the real one, and is plainly made up.
const token = `test-token-${'x'.repeat(33)}`;

function capture(pathname: string, hash: string, search = '') {
  const replaceState = vi.fn();
  captureFragmentToken({ pathname, search, hash }, { replaceState, state: { back: '/x' } });
  return replaceState;
}

describe('captureFragmentToken', () => {
  test.each(['/setup', '/activate', '/reset-password'])('takes the token of %s and removes the fragment', (path) => {
    const replaceState = capture(path, `#token=${token}`);
    expect(replaceState).toHaveBeenCalledWith({ back: '/x' }, '', path);
    expect(takeFragmentToken()).toBe(token);
  });

  test.each(['/setup/', '/activate/', '/reset-password//'])('takes the token of %s as well, so that it does not stay in the address', (path) => {
    const replaceState = capture(path, `#token=${token}`);
    expect(replaceState).toHaveBeenCalledWith({ back: '/x' }, '', path);
    expect(takeFragmentToken()).toBe(token);
  });

  test('gives the token once', () => {
    capture('/setup', `#token=${token}`);
    expect(takeFragmentToken()).toBe(token);
    expect(takeFragmentToken()).toBeUndefined();
  });

  test('keeps the query and drops everything else of the fragment', () => {
    const replaceState = capture('/activate', `#token=${token}&x=y`, '?lang=de');
    expect(replaceState).toHaveBeenCalledWith({ back: '/x' }, '', '/activate?lang=de');
    expect(takeFragmentToken()).toBe(token);
  });

  test.each(['', '#', '#token=', '#token=short', `#token=${token}%20`, `#token=<script>${token}`, '#other=1', `#${token}`])(
    'finds no token in %j',
    (hash) => {
      capture('/setup', hash);
      expect(takeFragmentToken()).toBeUndefined();
    },
  );

  test('removes a fragment of a token page even when it holds no token', () => {
    expect(capture('/setup', '#token=short')).toHaveBeenCalledOnce();
  });

  test('leaves other pages alone', () => {
    const replaceState = capture('/sign-in', '#error=oidc');
    expect(replaceState).not.toHaveBeenCalled();
    expect(takeFragmentToken()).toBeUndefined();
  });

  test('forgets a token that nobody took when the next page is captured', () => {
    capture('/setup', `#token=${token}`);
    capture('/sign-in', '');
    expect(takeFragmentToken()).toBeUndefined();
  });
});
