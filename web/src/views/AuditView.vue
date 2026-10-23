<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { onMounted } from 'vue';
import { api } from '../api/client';
import type { AuditEntry } from '../api/generated';
import AuditResource from '../components/AuditResource.vue';
import TimeStamp from '../components/TimeStamp.vue';
import { t } from '../i18n';
import { usePagedList } from '../usePagedList';

const list = usePagedList<AuditEntry>(async (cursor) => {
  const { body } = await api.call('listAuditEntries', { query: { limit: 50, cursor } });
  return { items: body.entries, next: body.next_cursor };
});

onMounted(list.reload);
</script>

<template>
  <section>
    <div class="page-head">
      <div>
        <h1>{{ t('audit.title') }}</h1>
        <p class="lede">{{ t('audit.intro') }}</p>
      </div>
      <button class="button button-ghost" type="button" :disabled="list.loading.value" @click="list.reload">{{ t('common.refresh') }}</button>
    </div>

    <p class="hint">{{ t('audit.personalData') }}</p>
    <p v-if="list.error.value" class="notice notice-error" role="alert">{{ t('audit.loadFailed') }} {{ list.error.value }}</p>
    <p v-if="!list.loaded.value && list.loading.value" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="list.loaded.value && list.items.value.length === 0" class="notice" role="status">{{ t('audit.empty') }}</p>
    <div v-else-if="list.items.value.length > 0" class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th scope="col">{{ t('audit.time') }}</th>
            <th scope="col">{{ t('audit.action') }}</th>
            <th scope="col">{{ t('audit.outcome') }}</th>
            <th scope="col">{{ t('audit.actor') }}</th>
            <th scope="col">{{ t('field.resource') }}</th>
            <th scope="col">{{ t('audit.changed') }}</th>
            <th scope="col">{{ t('audit.address') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="entry in list.items.value" :key="entry.id">
            <td><TimeStamp :value="entry.occurred_at" /></td>
            <td>
              <code class="mono action">{{ entry.action }}</code>
              <code v-if="entry.request_id" class="mono request" :title="t('audit.requestId')">{{ entry.request_id }}</code>
            </td>
            <td>
              <span class="badge" :class="{ 'badge-strong': entry.outcome === 'failure', 'badge-muted': entry.outcome === 'denied' }">{{ t(`auditOutcome.${entry.outcome}`) }}</span>
            </td>
            <td>
              <span class="actor">
                <bdi v-if="entry.actor.display_name">{{ entry.actor.display_name }}</bdi>
                <bdi v-if="entry.actor.email" class="email">{{ entry.actor.email }}</bdi>
                <span class="how">{{ t(`auditActor.${entry.actor.kind}`) }}, {{ t(`auditMethod.${entry.actor.auth_method}`) }}</span>
              </span>
            </td>
            <td>
              <AuditResource v-if="entry.resource" :resource="entry.resource" :action="entry.action" />
              <template v-else>{{ t('common.none') }}</template>
            </td>
            <td class="mono changed">{{ entry.changed_fields.length === 0 ? t('common.none') : entry.changed_fields.join(', ') }}</td>
            <td class="mono">{{ entry.client_ip ?? t('common.none') }}</td>
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

.action,
.request {
  display: block;
  overflow-wrap: anywhere;
}

.request {
  color: var(--slate);
  font-size: 0.6875rem;
}

.actor {
  display: grid;
  gap: 0.1rem;
}

.email,
.how {
  color: var(--slate);
  font-size: 0.8125rem;
  overflow-wrap: anywhere;
}

.changed {
  font-size: 0.8125rem;
  overflow-wrap: anywhere;
}
</style>
