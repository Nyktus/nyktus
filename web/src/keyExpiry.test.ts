// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, test } from 'vitest';
import { earliestExpiry, expiryAllowed, expiryTime, latestExpiry } from './keyExpiry';

const now = new Date('2026-10-23T17:30:00Z');

describe('the days on which a key may expire', () => {
  test('begin tomorrow, in UTC', () => {
    expect(earliestExpiry(now)).toBe('2026-10-24');
    expect(earliestExpiry(new Date('2026-12-31T23:59:59Z'))).toBe('2027-01-01');
  });

  test('end a day before three years from now', () => {
    expect(latestExpiry(now)).toBe('2029-10-22');
  });

  test('allow the first and the last day, and nothing outside them', () => {
    expect(expiryAllowed('2026-10-24', now)).toBe(true);
    expect(expiryAllowed('2029-10-22', now)).toBe(true);
    expect(expiryAllowed('2026-10-23', now)).toBe(false);
    expect(expiryAllowed('2029-10-23', now)).toBe(false);
    expect(expiryAllowed('', now)).toBe(false);
    expect(expiryAllowed('2027-1-1', now)).toBe(false);
  });

  test('handle the leap day', () => {
    expect(latestExpiry(new Date('2028-02-29T12:00:00Z'))).toBe('2031-02-28');
  });
});

test('a key that expires on a day stops working at the start of that day, in UTC', () => {
  expect(expiryTime('2027-01-31')).toBe('2027-01-31T00:00:00Z');
});

test('the time of the last day is within three years of the moment of the request', () => {
  const time = new Date(expiryTime(latestExpiry(now))).getTime();
  const limit = new Date(now.getTime());
  limit.setUTCFullYear(limit.getUTCFullYear() + 3);
  expect(time).toBeLessThanOrEqual(limit.getTime());
});
