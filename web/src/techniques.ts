// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

const technique = /^T[0-9]{4}(\.[0-9]{3})?$/;
const activity = /^EAC[0-9]{4}$/;

export interface ParsedTechniques {
  ids: string[];
  invalid: string[];
}

/**
 * Reads identifiers that a user typed, separated by commas, spaces or
 * line breaks. A repeated one counts once. The server checks them against the
 * ATT&CK version it bundles; this only tells a typo from an identifier.
 */
function parseIdentifiers(text: string, identifier: RegExp): ParsedTechniques {
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

/** Reads technique identifiers of MITRE ATT&CK, such as T1078 or T1003.001. */
export function parseTechniques(text: string): ParsedTechniques {
  return parseIdentifiers(text, technique);
}

/** Reads activity identifiers of MITRE Engage, such as EAC0005. */
export function parseEngageActivities(text: string): ParsedTechniques {
  return parseIdentifiers(text, activity);
}
