// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

export type PersonaKind = 'host' | 'name' | 'text';

export type PersonaProblem = 'required' | 'host' | 'text';

const host = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/;

/** The longest line of free text that the server accepts as a value of a persona. */
export const maxTextLength = 200;

/**
 * Checks a value of a persona before it is sent, by its kind, so that the user
 * does not wait for the server to refuse it. The server decides. The value is
 * checked as it is sent, without the spaces around it.
 */
export function checkPersonaValue(kind: PersonaKind, input: string): PersonaProblem | undefined {
  const value = input.trim();
  if (value === '') {
    return 'required';
  }
  switch (kind) {
    case 'host':
      return host.test(value) ? undefined : 'host';
    case 'text':
      return [...value].length <= maxTextLength && !/[\r\n]/.test(value) ? undefined : 'text';
    case 'name':
      return undefined;
  }
}
