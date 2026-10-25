// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { Scenario } from './api/generated';
import { t } from './i18n';

/** Where a scenario came from: by hand, or the deceptions that joined it. */
export function sourceLabel(scenario: Pick<Scenario, 'deceptions'>): string {
  if (scenario.deceptions.length === 0) {
    return t('scenarios.byHand');
  }
  return scenario.deceptions.map((d) => t('scenarios.fromDeception', { id: d.deception_id })).join('; ');
}
