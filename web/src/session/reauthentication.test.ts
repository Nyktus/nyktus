// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, test, vi } from 'vitest';
import { reauthenticationAddress, takeReauthenticationFailure } from './reauthentication';

describe('reauthenticationAddress', () => {
  test('names the page to return to, encoded', () => {
    expect(reauthenticationAddress('/alert-channels/abc')).toBe('/api/v1/oidc/reauthenticate?return_to=%2Falert-channels%2Fabc');
    expect(reauthenticationAddress('/alert-channels?x=1&y=2')).toBe('/api/v1/oidc/reauthenticate?return_to=%2Falert-channels%3Fx%3D1%26y%3D2');
  });

  test('leaves the fragment out', () => {
    expect(reauthenticationAddress('/alert-channels/new#top')).toBe('/api/v1/oidc/reauthenticate?return_to=%2Falert-channels%2Fnew');
  });

  test.each(['https://evil.example/x', '//evil.example/x', '/\\evil.example', 'alert-channels', '', `/${'a'.repeat(600)}`])(
    'leaves %j out, which is no path of the console',
    (path) => {
      expect(reauthenticationAddress(path)).toBe('/api/v1/oidc/reauthenticate');
    },
  );
});

describe('takeReauthenticationFailure', () => {
  const history = () => ({ state: { k: 1 }, replaceState: vi.fn() });

  test('tells that the provider could not confirm the user, and removes the fragment', () => {
    const h = history();
    expect(takeReauthenticationFailure({ pathname: '/alert-channels/abc', search: '?a=1', hash: '#error=reauthentication' }, h)).toBe(true);
    expect(h.replaceState).toHaveBeenCalledWith({ k: 1 }, '', '/alert-channels/abc?a=1');
  });

  test.each(['', '#error=oidc', '#error=reauthentication2', '#x'])('says nothing for %j and leaves the address alone', (hash) => {
    const h = history();
    expect(takeReauthenticationFailure({ pathname: '/a', search: '', hash }, h)).toBe(false);
    expect(h.replaceState).not.toHaveBeenCalled();
  });
});
