// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { onMounted, ref, type Ref } from 'vue';
import { api } from './api/client';

export interface EngageActivity {
  id: string;
  name: string;
}

let activities: Promise<EngageActivity[]> | undefined;

/**
 * The activities of MITRE Engage with their names, in English: MITRE publishes no translation. The list is the same
 * for everyone and for the life of the page, so it is read once; a failure is not kept, so that the next page asks again.
 */
export function loadEngageActivities(): Promise<EngageActivity[]> {
  activities ??= api
    .call('listCatalogEngageActivities', {})
    .then((result) => result.body.activities)
    .catch((failure: unknown) => {
      activities = undefined;
      throw failure;
    });
  return activities;
}

/** An identifier with its name in front of it, such as "Lures (EAC0005)"; the identifier alone while the name is unknown. */
export function engageLabel(id: string, names: ReadonlyMap<string, string>): string {
  const name = names.get(id);
  return name === undefined ? id : `${name} (${id})`;
}

/**
 * The names by identifier, empty until they are read and for good if they cannot be: the names are a courtesy, and the
 * identifier alone says the same.
 */
export function useEngageNames(): Ref<ReadonlyMap<string, string>> {
  const names = ref<ReadonlyMap<string, string>>(new Map());
  onMounted(() => {
    loadEngageActivities()
      .then((list) => {
        names.value = new Map(list.map((a) => [a.id, a.name]));
      })
      .catch(() => undefined);
  });
  return names;
}
