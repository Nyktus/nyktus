// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ref } from 'vue';
import { api } from './api/client';
import { ApiError } from './api/errors';
import type { Incident } from './api/generated';

export type ResourceType = Incident['resource_type'];

/** What is known of a resource that an incident or event names: its name, that it is gone, or nothing. */
export type ResourceEntry = { state: 'named'; name: string } | { state: 'gone' } | { state: 'unknown' };

const lookups = { scenario: 'getScenario', honeytoken: 'getHoneytoken', honeypot: 'getHoneypot' } as const;

/** How many names are asked for at the same time. */
const parallel = 6;

/**
 * Looks up the names of the resources that a page lists. Incidents and events carry
 * only the identifier of their resource, and the resource may be deleted by now, so a
 * name is asked for once per resource and a page shows the identifier until it is there.
 */
export function useResourceNames() {
  const entries = ref<Record<string, ResourceEntry>>({});
  const asked = new Set<string>();

  const key = (type: ResourceType, id: string): string => `${type}:${id}`;

  async function lookup(type: ResourceType, id: string): Promise<void> {
    let entry: ResourceEntry;
    try {
      const { body } = await api.call(lookups[type], { path: { id } });
      entry = { state: 'named', name: body.name };
    } catch (failure) {
      if (failure instanceof ApiError && failure.kind === 'not_found') {
        entry = { state: 'gone' };
      } else {
        entry = { state: 'unknown' };
        // A server that did not answer says nothing about the resource: the next page or refresh asks again.
        asked.delete(key(type, id));
      }
    }
    entries.value = { ...entries.value, [key(type, id)]: entry };
  }

  async function resolve(resources: readonly { resource_type: ResourceType; resource_id: string }[]): Promise<void> {
    const missing = new Map<string, { type: ResourceType; id: string }>();
    for (const resource of resources) {
      const k = key(resource.resource_type, resource.resource_id);
      if (!asked.has(k)) {
        asked.add(k);
        missing.set(k, { type: resource.resource_type, id: resource.resource_id });
      }
    }
    const queue = [...missing.values()];
    await Promise.all(
      Array.from({ length: Math.min(parallel, queue.length) }, async () => {
        for (let next = queue.shift(); next !== undefined; next = queue.shift()) {
          await lookup(next.type, next.id);
        }
      }),
    );
  }

  return { entries, resolve, key };
}
