// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

const identifier = /^T[0-9]{4}(\.[0-9]{3})?$/;

/** The most techniques that the server accepts for one resource. */
export const maxTechniques = 20;

export interface ParsedTechniques {
  ids: string[];
  invalid: string[];
}

/**
 * Reads technique identifiers that a user typed, separated by commas, spaces or
 * line breaks. A repeated one counts once. The server checks them against the
 * ATT&CK version it bundles; this only tells a typo from an identifier.
 */
export function parseTechniques(text: string): ParsedTechniques {
  const ids: string[] = [];
  const invalid: string[] = [];
  for (const raw of text.split(/[\s,;]+/)) {
    const value = raw.trim().toUpperCase();
    if (value === '') {
      continue;
    }
    if (!identifier.test(value)) {
      invalid.push(raw.trim());
    } else if (!ids.includes(value)) {
      ids.push(value);
    }
  }
  return { ids, invalid };
}
