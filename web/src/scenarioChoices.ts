// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { api } from './api/client';
import type { Scenario } from './api/generated';

/** The most pages of scenarios that a picker reads, so that it cannot loop without end. */
const maxPages = 10;

/** The scenarios that a picker offers, and whether there are more than it read. */
export async function loadScenarioChoices(): Promise<{ scenarios: Scenario[]; truncated: boolean }> {
  const scenarios: Scenario[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < maxPages; page++) {
    const { body } = await api.call('listScenarios', { query: { limit: 200, cursor } });
    scenarios.push(...body.scenarios);
    cursor = body.next_cursor;
    if (cursor === undefined) {
      break;
    }
  }
  return { scenarios, truncated: cursor !== undefined };
}
