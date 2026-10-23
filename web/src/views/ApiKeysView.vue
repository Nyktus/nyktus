<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { APIKey } from '../api/generated';
import { errorText } from '../api/messages';
import ConfirmDialog from '../components/ConfirmDialog.vue';
import TimeStamp from '../components/TimeStamp.vue';
import { t } from '../i18n';
import { session } from '../session';

const keys = ref<APIKey[]>([]);
const loaded = ref(false);
const error = ref<string | undefined>();
const revoking = ref<APIKey | undefined>();
const busy = ref(false);
const canWrite = computed(() => session.can('api_keys:write'));

function show(failure: unknown): string {
  return errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
}

function expired(key: APIKey): boolean {
  return new Date(key.expires_at).getTime() <= Date.now();
}

onMounted(async () => {
  try {
    keys.value = (await api.call('listAPIKeys', {})).body.api_keys;
    loaded.value = true;
  } catch (failure) {
    error.value = `${t('apiKeys.loadFailed')} ${show(failure)}`;
  }
});

async function revoke(): Promise<void> {
  const key = revoking.value;
  if (key === undefined) {
    return;
  }
  busy.value = true;
  error.value = undefined;
  try {
    await api.call('revokeAPIKey', { path: { id: key.id } });
    keys.value = keys.value.filter((other) => other.id !== key.id);
  } catch (failure) {
    if (failure instanceof ApiError && failure.kind === 'not_found') {
      // Someone else revoked it, or it expired and was removed: what the user wanted is so.
      keys.value = keys.value.filter((other) => other.id !== key.id);
    } else {
      error.value = show(failure);
    }
  } finally {
    busy.value = false;
    revoking.value = undefined;
  }
}
</script>

<template>
  <section>
    <div class="page-head">
      <div>
        <h1>{{ t('apiKeys.title') }}</h1>
        <p class="lede">{{ t('apiKeys.intro') }}</p>
      </div>
      <RouterLink v-if="canWrite" class="button button-primary" :to="{ name: 'api-key-new' }">{{ t('apiKeys.new') }}</RouterLink>
    </div>

    <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>
    <p v-if="!loaded && !error" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="loaded && keys.length === 0" class="notice" role="status">{{ t('apiKeys.empty') }}</p>
    <div v-else-if="keys.length > 0" class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th scope="col">{{ t('field.name') }}</th>
            <th scope="col">{{ t('apiKeys.scopes') }}</th>
            <th scope="col">{{ t('field.created') }}</th>
            <th scope="col">{{ t('apiKeys.expires') }}</th>
            <th scope="col">{{ t('apiKeys.lastUsed') }}</th>
            <th v-if="canWrite" scope="col"><span class="visually-hidden">{{ t('deliveries.actions') }}</span></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="key in keys" :key="key.id">
            <td>{{ key.name }}</td>
            <td class="mono scopes">{{ key.scopes.join(', ') }}</td>
            <td><TimeStamp :value="key.created_at" /></td>
            <td>
              <TimeStamp :value="key.expires_at" />
              <span v-if="expired(key)" class="badge badge-muted">{{ t('apiKeys.expired') }}</span>
            </td>
            <td>
              <TimeStamp v-if="key.last_used_at" :value="key.last_used_at" />
              <template v-else>{{ t('apiKeys.neverUsed') }}</template>
            </td>
            <td v-if="canWrite">
              <button class="button button-ghost" type="button" :disabled="busy" @click="revoking = key">{{ t('apiKeys.revoke.button') }}</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <ConfirmDialog
      v-if="canWrite"
      :open="revoking !== undefined"
      :title="t('apiKeys.revoke.title')"
      :confirm="t('apiKeys.revoke.confirm')"
      :busy="busy"
      @confirm="revoke"
      @cancel="revoking = undefined"
    >
      {{ t('apiKeys.revoke.body') }}
    </ConfirmDialog>
  </section>
</template>

<style scoped>
.scopes {
  font-size: 0.8125rem;
  overflow-wrap: anywhere;
}
</style>
