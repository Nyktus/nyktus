<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted } from 'vue';
import { api } from '../api/client';
import type { Scenario } from '../api/generated';
import DocsHint from '../components/DocsHint.vue';
import TimeStamp from '../components/TimeStamp.vue';
import { t } from '../i18n';
import { session } from '../session';
import { usePagedList } from '../usePagedList';

const list = usePagedList<Scenario>(async (cursor) => {
  const { body } = await api.call('listScenarios', { query: { limit: 50, cursor } });
  return { items: body.scenarios, next: body.next_cursor };
});

const canWrite = computed(() => session.can('scenarios:write'));

onMounted(list.reload);
</script>

<template>
  <section>
    <div class="page-head">
      <div>
        <h1>{{ t('scenarios.title') }}</h1>
        <DocsHint />
      </div>
      <div v-if="canWrite" class="actions-row">
        <RouterLink class="button button-ghost" :to="{ name: 'catalog' }">{{ t('scenarios.apply') }}</RouterLink>
        <RouterLink class="button button-primary" :to="{ name: 'scenario-new' }">{{ t('scenarios.new') }}</RouterLink>
      </div>
    </div>

    <p v-if="list.error.value" class="notice notice-error" role="alert">{{ t('scenarios.loadFailed') }} {{ list.error.value }}</p>

    <p v-if="!list.loaded.value && list.loading.value" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="list.loaded.value && list.items.value.length === 0" class="notice" role="status">{{ t('scenarios.empty') }}</p>
    <div v-else-if="list.items.value.length > 0" class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th scope="col">{{ t('field.name') }}</th>
            <th scope="col">{{ t('scenarios.source') }}</th>
            <th scope="col">{{ t('field.created') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="scenario in list.items.value" :key="scenario.id">
            <td>
              <RouterLink :to="{ name: 'scenario', params: { id: scenario.id } }">{{ scenario.name }}</RouterLink>
            </td>
            <td>{{ scenario.deception_id === null ? t('scenarios.byHand') : t('scenarios.fromDeception', { id: scenario.deception_id }) }}</td>
            <td><TimeStamp :value="scenario.created_at" /></td>
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
