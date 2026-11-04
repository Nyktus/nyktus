// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { de } from './de';
import { en } from './en';
import { formatMinutes, locale, setLocale, t } from './index';
import { initialLocale } from './preference';

const placeholders = (text: string): string[] => [...text.matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((m) => m[1] ?? '').sort();

describe('the catalogs', () => {
  test('German has the keys of English and no other', () => {
    expect(Object.keys(de).sort()).toEqual(Object.keys(en).sort());
  });

  test('no text is empty', () => {
    for (const [key, text] of [...Object.entries(en), ...Object.entries(de)]) {
      expect(text.trim(), key).not.toBe('');
    }
  });

  test('every text has the placeholders of its English original', () => {
    for (const [key, text] of Object.entries(en)) {
      expect(placeholders(de[key as keyof typeof de]), key).toEqual(placeholders(text));
    }
  });

  test('no text holds markup, because texts are shown as text', () => {
    for (const [key, text] of [...Object.entries(en), ...Object.entries(de)]) {
      expect(text, key).not.toMatch(/[<>]/);
    }
  });
});

describe('t', () => {
  beforeEach(() => {
    localStorage.clear();
    setLocale('en');
  });

  test('inserts the values as they are', () => {
    expect(t('scenarios.addDeception.already', { title: '<img src=x onerror=alert(1)> {title}' })).toBe(
      '<img src=x onerror=alert(1)> {title} (already part of this scenario)',
    );
  });

  test('follows the language', () => {
    expect(t('menu.signOut')).toBe('Sign out');
    setLocale('de');
    expect(t('menu.signOut')).toBe('Abmelden');
    expect(document.documentElement.lang).toBe('de');
  });
});

describe('the language', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  test('is the one the user chose', () => {
    localStorage.setItem('nyktus.locale', 'de');
    expect(initialLocale(['en-US'])).toBe('de');
  });

  test('is otherwise the first language of the browser that the console has', () => {
    expect(initialLocale(['fr-FR', 'de-AT', 'en'])).toBe('de');
    expect(initialLocale(['EN-gb'])).toBe('en');
  });

  test('is English when nothing matches', () => {
    expect(initialLocale(['fr', 'ja'])).toBe('en');
    expect(initialLocale([])).toBe('en');
  });

  test('ignores a stored value that is not a language', () => {
    localStorage.setItem('nyktus.locale', '<script>');
    expect(initialLocale(['de'])).toBe('de');
  });

  test('is found without storage', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new DOMException('blocked', 'SecurityError');
    });
    expect(initialLocale(['de'])).toBe('de');
  });

  test('can be chosen without storage', () => {
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('full', 'QuotaExceededError');
    });
    setLocale('de');
    expect(locale.value).toBe('de');
    setLocale('en');
  });
});

describe('formatMinutes', () => {
  beforeEach(() => {
    setLocale('en');
  });

  test('rounds up to whole minutes, at least one', () => {
    expect(formatMinutes(840)).toBe('14 minutes');
    expect(formatMinutes(841)).toBe('15 minutes');
    expect(formatMinutes(1)).toBe('1 minute');
    expect(formatMinutes(0)).toBe('1 minute');
  });

  test('speaks the language', () => {
    setLocale('de');
    expect(formatMinutes(900)).toBe('15 Minuten');
  });
});
