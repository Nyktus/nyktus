<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue';
import { api } from '../api/client';
import type { Honeypot } from '../api/generated';
import DocsHint from '../components/DocsHint.vue';
import HoneypotStatusBadge from '../components/HoneypotStatusBadge.vue';
import SeverityBadge from '../components/SeverityBadge.vue';
import StateBadge from '../components/StateBadge.vue';
import TimeStamp from '../components/TimeStamp.vue';
import { t } from '../i18n';
import { session } from '../session';
import { usePagedList } from '../usePagedList';

const service = ref<'' | Honeypot['service']>('');
const state = ref<'' | 'true' | 'false'>('');

const list = usePagedList<Honeypot>(async (cursor) => {
  const { body } = await api.call('listHoneypots', {
    query: {
      limit: 50,
      cursor,
      service: service.value === '' ? undefined : service.value,
      enabled: state.value === '' ? undefined : state.value,
    },
  });
  return { items: body.honeypots, next: body.next_cursor };
});

const filtered = computed(() => service.value !== '' || state.value !== '');
const canWrite = computed(() => session.can('honeypots:write'));

onMounted(list.reload);
watch([service, state], list.reload);
</script>

<template>
  <section>
    <div class="page-head">
      <div>
        <h1>{{ t('honeypots.title') }}</h1>
        <DocsHint />
      </div>
      <RouterLink v-if="canWrite" class="button button-primary" :to="{ name: 'honeypot-new' }">{{ t('honeypots.new') }}</RouterLink>
    </div>

    <div class="toolbar">
      <div class="field">
        <label for="filter-service">{{ t('honeypots.filter.service') }}</label>
        <select id="filter-service" v-model="service">
          <option value="">{{ t('common.all') }}</option>
          <option value="ssh">{{ t('honeypotService.ssh') }}</option>
          <option value="telnet">{{ t('honeypotService.telnet') }}</option>
          <option value="postgres">{{ t('honeypotService.postgres') }}</option>
          <option value="ldap">{{ t('honeypotService.ldap') }}</option>
        </select>
      </div>
      <div class="field">
        <label for="filter-state">{{ t('honeypots.filter.state') }}</label>
        <select id="filter-state" v-model="state">
          <option value="">{{ t('common.all') }}</option>
          <option value="true">{{ t('state.enabled') }}</option>
          <option value="false">{{ t('state.disabled') }}</option>
        </select>
      </div>
    </div>

    <p v-if="list.error.value" class="notice notice-error" role="alert">{{ t('honeypots.loadFailed') }} {{ list.error.value }}</p>

    <p v-if="!list.loaded.value && list.loading.value" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="list.loaded.value && list.items.value.length === 0" class="notice" role="status">
      {{ filtered ? t('honeypots.emptyFiltered') : t('honeypots.empty') }}
    </p>
    <div v-else-if="list.items.value.length > 0" class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th scope="col">{{ t('field.name') }}</th>
            <th scope="col">{{ t('field.type') }}</th>
            <th scope="col">{{ t('field.state') }}</th>
            <th scope="col">{{ t('honeypots.status') }}</th>
            <th scope="col">{{ t('field.severity') }}</th>
            <th scope="col">{{ t('honeypots.lastSeen') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="honeypot in list.items.value" :key="honeypot.id">
            <td>
              <RouterLink :to="{ name: 'honeypot', params: { id: honeypot.id } }">{{ honeypot.name }}</RouterLink>
            </td>
            <td>{{ t(`honeypotService.${honeypot.service}`) }}</td>
            <td><StateBadge :enabled="honeypot.enabled" /></td>
            <td><HoneypotStatusBadge :status="honeypot.status" /></td>
            <td><SeverityBadge :severity="honeypot.severity" /></td>
            <td>
              <TimeStamp v-if="honeypot.last_seen_at" :value="honeypot.last_seen_at" />
              <span v-else>{{ t('honeypots.never') }}</span>
            </td>
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
