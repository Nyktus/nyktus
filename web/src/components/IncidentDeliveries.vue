<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { AlertDelivery } from '../api/generated';
import { errorText } from '../api/messages';
import { t } from '../i18n';
import { session } from '../session';
import TimeStamp from './TimeStamp.vue';

const props = defineProps<{ incidentId: string }>();

const deliveries = ref<AlertDelivery[]>([]);
const loaded = ref(false);
const error = ref<string | undefined>();
const busy = ref<string | undefined>();
const canRetry = computed(() => session.can('alert_channels:write'));
const canOpenChannel = computed(() => session.can('alert_channels:read'));

function show(failure: unknown): string {
  return errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
}

onMounted(async () => {
  try {
    deliveries.value = (await api.call('listIncidentDeliveries', { path: { id: props.incidentId } })).body.deliveries;
    loaded.value = true;
  } catch (failure) {
    error.value = `${t('deliveries.loadFailed')} ${show(failure)}`;
  }
});

async function retry(delivery: AlertDelivery): Promise<void> {
  error.value = undefined;
  busy.value = delivery.id;
  try {
    const { body } = await api.call('retryAlertDelivery', { path: { id: delivery.id } });
    deliveries.value = deliveries.value.map((d) => (d.id === body.id ? body : d));
  } catch (failure) {
    error.value = show(failure);
  } finally {
    busy.value = undefined;
  }
}
</script>

<template>
  <div class="stack">
    <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>
    <p v-if="loaded && deliveries.length === 0" class="notice" role="status">{{ t('deliveries.none') }}</p>
    <div v-else-if="deliveries.length > 0" class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th scope="col">{{ t('deliveries.channel') }}</th>
            <th scope="col">{{ t('field.status') }}</th>
            <th scope="col">{{ t('deliveries.attempts') }}</th>
            <th scope="col">{{ t('deliveries.lastAttempt') }}</th>
            <th scope="col">{{ t('deliveries.result') }}</th>
            <th v-if="canRetry" scope="col"><span class="visually-hidden">{{ t('deliveries.actions') }}</span></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="delivery in deliveries" :key="delivery.id">
            <td>
              <RouterLink v-if="canOpenChannel" :to="{ name: 'alert-channel', params: { id: delivery.channel_id } }">{{ delivery.channel_name }}</RouterLink>
              <template v-else>{{ delivery.channel_name }}</template>
              <span class="kind">{{ t(`alertChannelType.${delivery.channel_type}`) }}</span>
            </td>
            <td>
              <span class="badge" :class="{ 'badge-strong': delivery.status === 'dead', 'badge-muted': delivery.status === 'canceled' }">{{ t(`deliveryStatus.${delivery.status}`) }}</span>
            </td>
            <td>{{ delivery.attempts }}</td>
            <td>
              <TimeStamp v-if="delivery.last_attempt_at" :value="delivery.last_attempt_at" />
              <template v-else>{{ t('common.none') }}</template>
            </td>
            <td>
              <template v-if="delivery.status === 'delivered' && delivery.delivered_at"><TimeStamp :value="delivery.delivered_at" /></template>
              <template v-else-if="delivery.last_error !== null">
                {{ t(`deliveryError.${delivery.last_error}`) }}
                <template v-if="delivery.last_status_code !== null"> {{ t('deliveries.code', { code: delivery.last_status_code }) }}</template>
              </template>
              <template v-else-if="delivery.status === 'pending' && delivery.next_attempt_at">
                {{ t('deliveries.next') }} <TimeStamp :value="delivery.next_attempt_at" />
              </template>
              <template v-else>{{ t('common.none') }}</template>
            </td>
            <td v-if="canRetry">
              <button v-if="delivery.status === 'dead'" class="button button-ghost" type="button" :disabled="busy === delivery.id" @click="retry(delivery)">
                {{ t('deliveries.retry') }}
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.kind {
  display: block;
  color: var(--slate);
  font-size: 0.8125rem;
}
</style>
