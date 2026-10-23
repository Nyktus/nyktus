// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

export const maxRecipients = 10;

export interface ParsedRecipients {
  addresses: string[];
  invalid: string[];
  /** The same address twice, ignoring case, which the server refuses. */
  repeated: string[];
}

/** A bare `local@domain` in ASCII; the server checks the rest, this tells a typo from an address. */
const address = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;

/** Reads addresses that a user typed, separated by line breaks, commas, semicolons or spaces. */
export function parseRecipients(text: string): ParsedRecipients {
  const addresses: string[] = [];
  const invalid: string[] = [];
  const repeated: string[] = [];
  const seen = new Set<string>();
  for (const raw of text.split(/[\s,;]+/)) {
    const value = raw.trim();
    if (value === '') {
      continue;
    }
    if (!address.test(value) || !value.split('@')[1]?.includes('.')) {
      invalid.push(value);
    } else if (seen.has(value.toLowerCase())) {
      repeated.push(value);
    } else {
      seen.add(value.toLowerCase());
      addresses.push(value);
    }
  }
  return { addresses, invalid, repeated };
}
