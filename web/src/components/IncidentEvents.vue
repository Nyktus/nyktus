<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, watch } from 'vue';
import { api } from '../api/client';
import type { Event } from '../api/generated';
import { t } from '../i18n';
import { useResourceNames } from '../resourceNames';
import { usePagedList } from '../usePagedList';
import EventSummary from './EventSummary.vue';
import ResourceRef from './ResourceRef.vue';
import SeverityBadge from './SeverityBadge.vue';
import TimeStamp from './TimeStamp.vue';

const props = defineProps<{ incidentId: string; eventCount: number }>();

const list = usePagedList<Event>(async (cursor) => {
  const { body } = await api.call('listEvents', { query: { limit: 50, cursor, incident_id: props.incidentId } });
  return { items: body.events, next: body.next_cursor };
});

const names = useResourceNames();

// Events are deleted after the retention, but the incident keeps counting them.
const deleted = computed(() => list.loaded.value && list.next.value === undefined && list.items.value.length < props.eventCount);

onMounted(list.reload);
watch(list.items, (events) => void names.resolve(events));
watch(() => props.incidentId, list.reload);
</script>

<template>
  <div class="stack">
    <p v-if="list.error.value" class="notice notice-error" role="alert">{{ t('incident.eventsFailed') }} {{ list.error.value }}</p>
    <p v-if="!list.loaded.value && list.loading.value" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="list.loaded.value && list.items.value.length === 0" class="notice" role="status">{{ t('incident.eventsEmpty') }}</p>
    <div v-else-if="list.items.value.length > 0" class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th scope="col">{{ t('field.recorded') }}</th>
            <th scope="col">{{ t('incident.eventWhat') }}</th>
            <th scope="col">{{ t('field.resource') }}</th>
            <th scope="col">{{ t('field.severity') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="event in list.items.value" :key="event.id">
            <td>
              <RouterLink :to="{ name: 'event', params: { id: event.id } }"><TimeStamp :value="event.recorded_at" /></RouterLink>
            </td>
            <td><EventSummary :event="event" /></td>
            <td><ResourceRef :type="event.resource_type" :id="event.resource_id" :entry="names.entries.value[names.key(event.resource_type, event.resource_id)]" /></td>
            <td><SeverityBadge :severity="event.severity" /></td>
          </tr>
        </tbody>
      </table>
    </div>
    <p v-if="deleted" class="hint">{{ t('incident.eventsCut', { count: eventCount }) }}</p>
    <p v-if="list.next.value !== undefined" class="actions-row">
      <button class="button button-ghost" type="button" :disabled="list.loading.value" @click="list.more">{{ t('common.loadMore') }}</button>
    </p>
  </div>
</template>
