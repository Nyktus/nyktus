// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { computed, onMounted, ref, type ComputedRef } from 'vue';
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
 * The activities in the order of the list and their names by identifier, empty until they are read. `failed` says that they could not be, and `load`
 * asks again.
 */
export function useEngageActivities() {
  const activities = ref<EngageActivity[]>([]);
  const loaded = ref(false);
  const failed = ref(false);

  async function load(): Promise<void> {
    failed.value = false;
    try {
      activities.value = await loadEngageActivities();
      loaded.value = true;
    } catch {
      failed.value = true;
    }
  }

  const names = computed(() => new Map(activities.value.map((a) => [a.id, a.name])));

  onMounted(load);
  return { activities, names, loaded, failed, load };
}

/**
 * The names by identifier, empty until they are read and for good if they cannot be: the names are a courtesy, and the
 * identifier alone says the same.
 */
export function useEngageNames(): ComputedRef<ReadonlyMap<string, string>> {
  return useEngageActivities().names;
}
