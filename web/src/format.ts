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
