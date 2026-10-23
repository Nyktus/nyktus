<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { api } from '../api/client';
import type { Incident } from '../api/generated';
import IncidentStatusBadge from '../components/IncidentStatusBadge.vue';
import ResourceRef from '../components/ResourceRef.vue';
import SeverityBadge from '../components/SeverityBadge.vue';
import TimeStamp from '../components/TimeStamp.vue';
import { t } from '../i18n';
import { useResourceNames } from '../resourceNames';
import { usePagedList } from '../usePagedList';

type Filter = '' | 'open,acknowledged' | 'open' | 'acknowledged' | 'closed';

/** How often the page looks for a new incident while it is visible, in milliseconds. */
const pollEvery = 60_000;

const status = ref<Filter>('open,acknowledged');
const fresh = ref(false);

const list = usePagedList<Incident>(async (cursor) => {
  const { body } = await api.call('listIncidents', {
    query: { limit: 50, cursor, status: status.value === '' ? undefined : status.value },
  });
  return { items: body.incidents, next: body.next_cursor };
});

const names = useResourceNames();

async function refresh(): Promise<void> {
  fresh.value = false;
  await list.reload();
}

/**
 * Asks for the newest incident only. The answer never replaces the list: pages that
 * the user loaded stay, and nothing moves under the cursor. It only tells that there
 * is something to show.
 */
async function look(): Promise<void> {
  if (document.visibilityState !== 'visible' || !list.loaded.value || list.loading.value) {
    return;
  }
  const asked = status.value;
  try {
    const { body } = await api.call('listIncidents', { query: { limit: 1, status: asked === '' ? undefined : asked } });
    if (asked === status.value) {
      const newest = body.incidents[0];
      // The newest incident that is not in the list is new; one that moved up because the top one was closed is not.
      fresh.value = newest !== undefined && !list.items.value.some((incident) => incident.id === newest.id);
    }
  } catch {
    // The hint is a convenience; a failed look says nothing.
  }
}

let timer: ReturnType<typeof setInterval> | undefined;

onMounted(() => {
  void list.reload();
  timer = setInterval(() => void look(), pollEvery);
});
onBeforeUnmount(() => {
  clearInterval(timer);
});

watch(status, () => void refresh());
watch(list.items, (incidents) => void names.resolve(incidents));
</script>

<template>
  <section>
    <div class="page-head">
      <div>
        <h1>{{ t('incidents.title') }}</h1>
        <p class="lede">{{ t('incidents.intro') }}</p>
      </div>
      <button class="button button-ghost" type="button" :disabled="list.loading.value" @click="refresh">{{ t('incidents.refresh') }}</button>
    </div>

    <div class="toolbar">
      <div class="field">
        <label for="filter-status">{{ t('field.status') }}</label>
        <select id="filter-status" v-model="status">
          <option value="open,acknowledged">{{ t('incidents.filter.active') }}</option>
          <option value="">{{ t('common.all') }}</option>
          <option value="open">{{ t('incidentStatus.open') }}</option>
          <option value="acknowledged">{{ t('incidentStatus.acknowledged') }}</option>
          <option value="closed">{{ t('incidentStatus.closed') }}</option>
        </select>
      </div>
    </div>

    <p v-if="fresh" class="notice" role="status">
      {{ t('incidents.fresh') }}
      <button class="button button-ghost" type="button" @click="refresh">{{ t('incidents.freshAction') }}</button>
    </p>

    <p v-if="list.error.value" class="notice notice-error" role="alert">{{ t('incidents.loadFailed') }} {{ list.error.value }}</p>

    <p v-if="!list.loaded.value && list.loading.value" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="list.loaded.value && list.items.value.length === 0" class="notice" role="status">
      {{ status === '' ? t('incidents.empty') : status === 'open,acknowledged' ? t('incidents.emptyActive') : t('incidents.emptyFiltered') }}
    </p>
    <div v-else-if="list.items.value.length > 0" class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th scope="col">{{ t('field.opened') }}</th>
            <th scope="col">{{ t('field.status') }}</th>
            <th scope="col">{{ t('field.severity') }}</th>
            <th scope="col">{{ t('field.resource') }}</th>
            <th scope="col">{{ t('field.events') }}</th>
            <th scope="col">{{ t('field.lastEvent') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="incident in list.items.value" :key="incident.id">
            <td>
              <RouterLink :to="{ name: 'incident', params: { id: incident.id } }"><TimeStamp :value="incident.opened_at" /></RouterLink>
            </td>
            <td><IncidentStatusBadge :status="incident.status" /></td>
            <td><SeverityBadge :severity="incident.severity" /></td>
            <td><ResourceRef :type="incident.resource_type" :id="incident.resource_id" :entry="names.entries.value[names.key(incident.resource_type, incident.resource_id)]" /></td>
            <td>{{ incident.event_count }}</td>
            <td><TimeStamp :value="incident.last_event_at" /></td>
          </tr>
        </tbody>
      </table>
    </div>

    <p v-if="list.next.value !== undefined" class="actions-row more">
      <button class="button button-ghost" type="button" :disabled="list.loading.value" @click="list.more">{{ t('common.loadMore') }}</button>
    </p>
  </section>
</template>

<style scoped>
.more {
  margin-top: 1rem;
}
</style>
