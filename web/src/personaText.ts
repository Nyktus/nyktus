// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { t } from './i18n';
import type { PersonaField, PersonaProblem } from './personaRules';

/** The text that tells the user what is wrong with the value of a field. */
export function personaProblemText(field: Pick<PersonaField, 'label'>, problem: PersonaProblem): string {
  switch (problem) {
    case 'required':
      return t('persona.required', { label: field.label });
    case 'host':
      return t('persona.hostInvalid', { label: field.label });
    case 'text':
      return t('persona.textInvalid', { label: field.label });
  }
}

/** The texts for the fields that have a problem, by key. */
export function personaProblemTexts(fields: readonly PersonaField[], problems: Readonly<Record<string, PersonaProblem>>): Record<string, string> {
  const found: Record<string, string> = {};
  for (const field of fields) {
    const problem = problems[field.key];
    if (problem !== undefined) {
      found[field.key] = personaProblemText(field, problem);
    }
  }
  return found;
}
