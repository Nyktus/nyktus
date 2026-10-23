// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, test } from 'vitest';
import { isConsolePath, rememberReturnPath, takeReturnPath } from './returnTo';

describe('isConsolePath', () => {
  test.each(['/', '/incidents', '/incidents/8d1c0f0e-1111-4222-8333-944444444444', '/incidents?status=open&limit=10', '/a/b%20c'])(
    'accepts %s',
    (path) => {
      expect(isConsolePath(path)).toBe(true);
    },
  );

  // Each of these reaches another host or runs code when a browser follows it.
  test.each([
    '',
    'incidents',
    '//evil.example',
    '//evil.example/path',
    '/\\evil.example',
    '\\\\evil.example',
    '/\\/evil.example',
    'https://evil.example',
    'http://evil.example/',
    'javascript:alert(1)',
    'data:text/html,<script>',
    '/ /evil',
    '/\tevil',
    '/\nevil',
    '/\u0000',
    '/\u00e9',
    `/${'a'.repeat(512)}`,
  ])('refuses %j', (path) => {
    expect(isConsolePath(path)).toBe(false);
  });
});

describe('the remembered path', () => {
  const known = () => true;

  test('is given back once', () => {
    rememberReturnPath('/incidents');
    expect(takeReturnPath(known)).toBe('/incidents');
    expect(takeReturnPath(known)).toBeUndefined();
  });

  test('is never one that is not a path of the console', () => {
    rememberReturnPath('//evil.example');
    expect(takeReturnPath(known)).toBeUndefined();
  });

  test('is dropped when the router has no page for it', () => {
    rememberReturnPath('/nothing-here');
    expect(takeReturnPath(() => false)).toBeUndefined();
    expect(takeReturnPath(known)).toBeUndefined();
  });

  test('is replaced by the next one', () => {
    rememberReturnPath('/a');
    rememberReturnPath('/b');
    expect(takeReturnPath(known)).toBe('/b');
  });
});
