// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, test } from 'vitest';
import { parseRecipients } from './recipients';

describe('parseRecipients', () => {
  test('reads addresses separated by line breaks, commas, semicolons and spaces', () => {
    expect(parseRecipients('soc@example.com\nit@example.com, ops@example.org; on-call@example.net  last@example.io').addresses).toEqual([
      'soc@example.com',
      'it@example.com',
      'ops@example.org',
      'on-call@example.net',
      'last@example.io',
    ]);
  });

  test('is empty for nothing', () => {
    expect(parseRecipients(' \n ,; ')).toEqual({ addresses: [], invalid: [], repeated: [] });
  });

  test.each(['plain', '@example.com', 'a@', 'a@b', 'Ada <ada@example.com>', '"a"@example.com', 'a@exa mple.com', 'a@b@example.com', 'ada@ex\u00E4mple.com', 'a@-example.com'])(
    'does not take %j for an address',
    (value) => {
      expect(parseRecipients(value).addresses).toEqual([]);
      expect(parseRecipients(value).invalid.length).toBeGreaterThan(0);
    },
  );

  test('tells an address that repeats, ignoring case, and keeps the first', () => {
    expect(parseRecipients('Soc@example.com soc@EXAMPLE.com')).toEqual({ addresses: ['Soc@example.com'], invalid: [], repeated: ['soc@EXAMPLE.com'] });
  });

  test('keeps an internationalized domain in its ASCII form', () => {
    expect(parseRecipients('soc@xn--bcher-kva.example').addresses).toEqual(['soc@xn--bcher-kva.example']);
  });
});
