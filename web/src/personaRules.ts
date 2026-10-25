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

/** A value that the catalog asks for, as the API describes it. */
export interface PersonaField {
  key: string;
  kind: PersonaKind;
  label: string;
  example: string;
}

/**
 * Checks the values of the fields that the user has to give, by key. A key that the scenario
 * has already is left out: its value stays as it is, whatever the form holds.
 */
export function personaProblems(fields: readonly PersonaField[], values: Readonly<Record<string, string>>, fixed: Readonly<Record<string, string>> = {}): Record<string, PersonaProblem> {
  const found: Record<string, PersonaProblem> = {};
  for (const field of fields) {
    if (Object.hasOwn(fixed, field.key)) {
      continue;
    }
    const problem = checkPersonaValue(field.kind, values[field.key] ?? '');
    if (problem !== undefined) {
      found[field.key] = problem;
    }
  }
  return found;
}

/** The values to send: the trimmed input for every key the scenario lacks, and nothing for a key it has. */
export function personaToSend(fields: readonly PersonaField[], values: Readonly<Record<string, string>>, fixed: Readonly<Record<string, string>> = {}): Record<string, string> {
  const out: Record<string, string> = {};
  for (const field of fields) {
    if (!Object.hasOwn(fixed, field.key)) {
      out[field.key] = (values[field.key] ?? '').trim();
    }
  }
  return out;
}
