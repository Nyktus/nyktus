// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ref } from 'vue';
import { de } from './de';
import { en, type MessageKey } from './en';
import { initialLocale, rememberLocale, type Locale } from './preference';

export type { MessageKey } from './en';
export { locales, type Locale } from './preference';

/** The names of the languages, each in its own language. */
export const languageNames: Record<Locale, string> = { en: 'English', de: 'Deutsch' };

type Placeholders<S extends string> = S extends `${string}{${infer P}}${infer Rest}` ? P | Placeholders<Rest> : never;

/** The texts that have no placeholder, which a page can name without values. */
export type PlainMessageKey = {
  [K in MessageKey]: [Placeholders<(typeof en)[K]>] extends [never] ? K : never;
}[MessageKey];

/** The placeholders of a text, so that a call must name every one of them and no other. */
type Params<K extends MessageKey> = [Placeholders<(typeof en)[K]>] extends [never]
  ? []
  : [params: Record<Placeholders<(typeof en)[K]>, string | number>];

const catalogs: Record<Locale, Record<MessageKey, string>> = { en, de };

export const locale = ref<Locale>(initialLocale(globalThis.navigator?.languages ?? []));

export function setLocale(next: Locale): void {
  locale.value = next;
  rememberLocale(next);
  document.documentElement.lang = next;
}

/**
 * Returns a text in the current language. The text is plain text: it never
 * becomes markup, and the values of the placeholders are inserted as they are.
 */
export function t<K extends MessageKey>(key: K, ...args: Params<K>): string {
  const params: Record<string, string | number> = args[0] ?? {};
  return catalogs[locale.value][key].replace(/\{([A-Za-z0-9_]+)\}/g, (_, name: string) => String(params[name] ?? ''));
}

/** Formats a duration in whole minutes, rounded up, in the current language. */
export function formatMinutes(seconds: number): string {
  const minutes = Math.max(1, Math.ceil(seconds / 60));
  return new Intl.NumberFormat(locale.value, { style: 'unit', unit: 'minute', unitDisplay: 'long' }).format(minutes);
}
