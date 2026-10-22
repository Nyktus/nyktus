<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue';
import { api } from '../api/client';
import type { Honeytoken } from '../api/generated';
import SeverityBadge from '../components/SeverityBadge.vue';
import StateBadge from '../components/StateBadge.vue';
import TimeStamp from '../components/TimeStamp.vue';
import { t } from '../i18n';
import { session } from '../session';
import { usePagedList } from '../usePagedList';

const type = ref<'' | Honeytoken['type']>('');
const state = ref<'' | 'true' | 'false'>('');

const list = usePagedList<Honeytoken>(async (cursor) => {
  const { body } = await api.call('listHoneytokens', {
    query: {
      limit: 50,
      cursor,
      type: type.value === '' ? undefined : type.value,
      enabled: state.value === '' ? undefined : state.value,
    },
  });
  return { items: body.honeytokens, next: body.next_cursor };
});

const filtered = computed(() => type.value !== '' || state.value !== '');
const canWrite = computed(() => session.can('honeytokens:write'));

onMounted(list.reload);
watch([type, state], list.reload);
</script>

<template>
  <section>
    <div class="page-head">
      <div>
        <h1>{{ t('honeytokens.title') }}</h1>
        <p class="lede">{{ t('honeytokens.intro') }}</p>
      </div>
      <RouterLink v-if="canWrite" class="button button-primary" :to="{ name: 'honeytoken-new' }">{{ t('honeytokens.new') }}</RouterLink>
    </div>

    <div class="toolbar">
      <div class="field">
        <label for="filter-type">{{ t('honeytokens.filter.type') }}</label>
        <select id="filter-type" v-model="type">
          <option value="">{{ t('common.all') }}</option>
          <option value="web_url">{{ t('honeytokenType.web_url') }}</option>
          <option value="web_image">{{ t('honeytokenType.web_image') }}</option>
          <option value="dns">{{ t('honeytokenType.dns') }}</option>
        </select>
      </div>
      <div class="field">
        <label for="filter-state">{{ t('honeytokens.filter.state') }}</label>
        <select id="filter-state" v-model="state">
          <option value="">{{ t('common.all') }}</option>
          <option value="true">{{ t('state.enabled') }}</option>
          <option value="false">{{ t('state.disabled') }}</option>
        </select>
      </div>
    </div>

    <p v-if="list.error.value" class="notice notice-error" role="alert">{{ t('honeytokens.loadFailed') }} {{ list.error.value }}</p>

    <p v-if="!list.loaded.value && list.loading.value" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="list.loaded.value && list.items.value.length === 0" class="notice" role="status">
      {{ filtered ? t('honeytokens.emptyFiltered') : t('honeytokens.empty') }}
    </p>
    <div v-else-if="list.items.value.length > 0" class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th scope="col">{{ t('field.name') }}</th>
            <th scope="col">{{ t('field.type') }}</th>
            <th scope="col">{{ t('field.state') }}</th>
            <th scope="col">{{ t('field.severity') }}</th>
            <th scope="col">{{ t('field.created') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="honeytoken in list.items.value" :key="honeytoken.id">
            <td>
              <RouterLink :to="{ name: 'honeytoken', params: { id: honeytoken.id } }">{{ honeytoken.name }}</RouterLink>
            </td>
            <td>{{ t(`honeytokenType.${honeytoken.type}`) }}</td>
            <td><StateBadge :enabled="honeytoken.enabled" /></td>
            <td><SeverityBadge :severity="honeytoken.severity" /></td>
            <td><TimeStamp :value="honeytoken.created_at" /></td>
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
