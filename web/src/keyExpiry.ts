// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

const day = 24 * 60 * 60 * 1000;

/** Formats a time as the date of its day in UTC, such as 2026-10-24. */
function dateOf(time: Date): string {
  return time.toISOString().slice(0, 10);
}

/** The first day on which a key may expire: tomorrow, so that its expiry lies in the future. */
export function earliestExpiry(now: Date): string {
  return dateOf(new Date(now.getTime() + day));
}

/**
 * The last day on which a key may expire. The server accepts at most three years;
 * a key that expires at the start of the day before that day is always within them.
 */
export function latestExpiry(now: Date): string {
  const limit = new Date(now.getTime());
  limit.setUTCFullYear(limit.getUTCFullYear() + 3);
  return dateOf(new Date(limit.getTime() - day));
}

/** The time at which a key that expires on a day stops working: the start of the day, in UTC. */
export function expiryTime(date: string): string {
  return `${date}T00:00:00Z`;
}

/** Tells whether a date is a day on which a key may expire. */
export function expiryAllowed(date: string, now: Date): boolean {
  return /^\d{4}-\d{2}-\d{2}$/.test(date) && date >= earliestExpiry(now) && date <= latestExpiry(now);
}
