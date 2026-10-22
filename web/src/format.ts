// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { Locale } from './i18n';

/**
 * Formats a time of the server, which is in UTC, in the time zone of the browser.
 * The UTC time stays available to the user, because the logs and the audit log
 * name times in UTC.
 */
export function formatDateTime(iso: string, locale: Locale): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return iso;
  }
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}

/** The size of a file in the unit that reads best, in the language given. */
export function formatSize(bytes: number, locale: Locale): { unit: 'bytes' | 'kib' | 'mib'; count: string } {
  const number = (n: number): string => new Intl.NumberFormat(locale, { maximumFractionDigits: 1 }).format(n);
  if (bytes < 1024) {
    return { unit: 'bytes', count: number(bytes) };
  }
  if (bytes < 1024 * 1024) {
    return { unit: 'kib', count: number(bytes / 1024) };
  }
  return { unit: 'mib', count: number(bytes / (1024 * 1024)) };
}
