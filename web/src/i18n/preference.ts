// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

export const locales = ['en', 'de'] as const;
export type Locale = (typeof locales)[number];

const key = 'nyktus.locale';

function isLocale(value: unknown): value is Locale {
  return typeof value === 'string' && (locales as readonly string[]).includes(value);
}

/**
 * Returns the language the user chose, or else the first language of the
 * browser that the console has, or English. The choice is the only thing the
 * console keeps in the browser: it is no secret and no credential. The storage
 * can be missing or refuse, as in a private window, and the console works
 * without it.
 */
export function initialLocale(languages: readonly string[]): Locale {
  try {
    const stored = localStorage.getItem(key);
    if (isLocale(stored)) {
      return stored;
    }
  } catch {
    // Without storage, the language of the browser decides.
  }
  for (const language of languages) {
    const base = language.toLowerCase().split('-')[0];
    if (isLocale(base)) {
      return base;
    }
  }
  return 'en';
}

export function rememberLocale(locale: Locale): void {
  try {
    localStorage.setItem(key, locale);
  } catch {
    // The choice then holds until the page is closed.
  }
}
