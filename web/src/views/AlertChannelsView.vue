<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { AlertChannel } from '../api/generated';
import { errorText } from '../api/messages';
import StateBadge from '../components/StateBadge.vue';
import TimeStamp from '../components/TimeStamp.vue';
import { t } from '../i18n';
import { session } from '../session';

const channels = ref<AlertChannel[]>([]);
const loaded = ref(false);
const error = ref<string | undefined>();
const canWrite = computed(() => session.can('alert_channels:write'));

onMounted(async () => {
  try {
    channels.value = (await api.call('listAlertChannels', {})).body.alert_channels;
    loaded.value = true;
  } catch (failure) {
    error.value = errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
  }
});
</script>

<template>
  <section>
    <div class="page-head">
      <div>
        <h1>{{ t('alerts.title') }}</h1>
        <p class="lede">{{ t('alerts.intro') }}</p>
      </div>
      <RouterLink v-if="canWrite" class="button button-primary" :to="{ name: 'alert-channel-new' }">{{ t('alerts.new') }}</RouterLink>
    </div>

    <p v-if="error" class="notice notice-error" role="alert">{{ t('alerts.loadFailed') }} {{ error }}</p>
    <p v-else-if="!loaded" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="channels.length === 0" class="notice" role="status">{{ t('alerts.empty') }}</p>
    <div v-else class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th scope="col">{{ t('field.name') }}</th>
            <th scope="col">{{ t('field.type') }}</th>
            <th scope="col">{{ t('field.state') }}</th>
            <th scope="col">{{ t('alerts.target') }}</th>
            <th scope="col">{{ t('field.created') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="channel in channels" :key="channel.id">
            <td>
              <RouterLink :to="{ name: 'alert-channel', params: { id: channel.id } }">{{ channel.name }}</RouterLink>
            </td>
            <td>{{ t(`alertChannelType.${channel.type}`) }}</td>
            <td><StateBadge :enabled="channel.enabled" /></td>
            <td class="mono">{{ channel.recipients !== null ? channel.recipients.join(', ') : (channel.target ?? t('common.none')) }}</td>
            <td><TimeStamp :value="channel.created_at" /></td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>
