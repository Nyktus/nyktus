// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ref, shallowRef } from 'vue';
import { ApiError } from './api/errors';
import { errorText } from './api/messages';

export interface Page<T> {
  items: T[];
  next: string | undefined;
}

/**
 * A list that the server pages with a cursor after the last item. A new load, as
 * after a change of a filter, drops what is still on its way, so that a slow answer
 * for the old filter cannot replace the list of the new one.
 */
export function usePagedList<T>(fetchPage: (cursor: string | undefined) => Promise<Page<T>>) {
  const items = shallowRef<T[]>([]);
  const next = ref<string | undefined>();
  const loading = ref(false);
  const loaded = ref(false);
  const error = ref<string | undefined>();
  let generation = 0;

  async function run(cursor: string | undefined, append: boolean): Promise<void> {
    const mine = ++generation;
    loading.value = true;
    error.value = undefined;
    try {
      const page = await fetchPage(cursor);
      if (mine !== generation) {
        return;
      }
      items.value = append ? [...items.value, ...page.items] : page.items;
      next.value = page.next;
      loaded.value = true;
    } catch (failure) {
      if (mine === generation) {
        error.value = errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
        if (!append) {
          // What is shown belongs to the filter before, and its cursor to nothing that is asked for now.
          items.value = [];
          next.value = undefined;
          loaded.value = false;
        }
      }
    } finally {
      if (mine === generation) {
        loading.value = false;
      }
    }
  }

  return {
    items,
    next,
    loading,
    loaded,
    error,
    reload: () => run(undefined, false),
    more: () => (next.value === undefined ? Promise.resolve() : run(next.value, true)),
  };
}
