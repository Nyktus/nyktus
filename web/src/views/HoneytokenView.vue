<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { Honeytoken, OperationTypes } from '../api/generated';
import { errorText } from '../api/messages';
import ConfirmDialog from '../components/ConfirmDialog.vue';
import CopyButton from '../components/CopyButton.vue';
import HoneytokenForm from '../components/HoneytokenForm.vue';
import QrCode from '../components/QrCode.vue';
import ScenarioAssignment from '../components/ScenarioAssignment.vue';
import SeverityBadge from '../components/SeverityBadge.vue';
import StateBadge from '../components/StateBadge.vue';
import TimeStamp from '../components/TimeStamp.vue';
import { t } from '../i18n';
import { session } from '../session';

const route = useRoute();
const router = useRouter();

const id = computed(() => String(route.params.id));
const honeytoken = ref<Honeytoken | undefined>();
const loading = ref(true);
const missing = ref(false);
const error = ref<string | undefined>();
const saved = ref(false);
const busy = ref(false);
const confirming = ref(false);
// The QR code of a URL that may be a secret appears on request only.
const showQr = ref(false);
const created = computed(() => route.query.created === '1');
const canWrite = computed(() => session.can('honeytokens:write'));

function show(failure: unknown): string {
  return errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
}

async function load(): Promise<void> {
  loading.value = true;
  error.value = undefined;
  try {
    honeytoken.value = (await api.call('getHoneytoken', { path: { id: id.value } })).body;
  } catch (failure) {
    if (failure instanceof ApiError && failure.kind === 'not_found') {
      missing.value = true;
    } else {
      error.value = show(failure);
    }
  } finally {
    loading.value = false;
  }
}

async function update(body: OperationTypes['updateHoneytoken']['body']): Promise<void> {
  error.value = undefined;
  saved.value = false;
  if (Object.keys(body).length === 0) {
    saved.value = true;
    return;
  }
  busy.value = true;
  try {
    honeytoken.value = (await api.call('updateHoneytoken', { path: { id: id.value }, body })).body;
    saved.value = true;
  } catch (failure) {
    error.value = show(failure);
  } finally {
    busy.value = false;
  }
}

async function remove(): Promise<void> {
  busy.value = true;
  try {
    await api.call('deleteHoneytoken', { path: { id: id.value } });
    await router.replace({ name: 'honeytokens' });
  } catch (failure) {
    confirming.value = false;
    error.value = show(failure);
  } finally {
    busy.value = false;
  }
}

onMounted(load);
</script>

<template>
  <section>
    <p><RouterLink :to="{ name: 'honeytokens' }">{{ t('honeytokens.back') }}</RouterLink></p>

    <p v-if="loading" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="missing" class="notice" role="status">{{ t('error.not_found') }}</p>

    <template v-else-if="honeytoken">
      <div class="page-head">
        <div>
          <h1>{{ honeytoken.name }}</h1>
          <p class="badges">
            <StateBadge :enabled="honeytoken.enabled" />
            <SeverityBadge :severity="honeytoken.severity" />
            <span class="badge">{{ t(`honeytokenType.${honeytoken.type}`) }}</span>
          </p>
        </div>
        <button v-if="canWrite" class="button button-ghost" type="button" @click="confirming = true">{{ t('common.delete') }}</button>
      </div>

      <p v-if="created" class="notice notice-ok" role="status">{{ t('honeytokens.created') }}</p>
      <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>

      <div class="section panel">
        <h2>{{ t('honeytokens.place.title') }}</h2>
        <div v-if="honeytoken.trigger_url" class="place">
          <div class="stack">
            <div class="row">
              <code class="mono value">{{ honeytoken.trigger_url }}</code>
              <CopyButton :value="honeytoken.trigger_url" />
            </div>
            <p class="hint">{{ t('honeytokens.place.fixed') }}</p>
            <p v-if="honeytoken.type === 'web_url'" class="hint">{{ t('honeytokens.place.link') }}</p>
          </div>
          <div v-if="honeytoken.type === 'web_url'" class="qr">
            <button
              class="button button-ghost"
              type="button"
              aria-controls="honeytoken-qr"
              :aria-expanded="showQr"
              @click="showQr = !showQr"
            >
              {{ showQr ? t('honeytokens.qr.hide') : t('honeytokens.qr.show') }}
            </button>
            <div v-if="showQr" id="honeytoken-qr" class="qr-code">
              <QrCode :text="honeytoken.trigger_url" :label="t('honeytokens.qr.label')" />
              <p class="hint">{{ t('honeytokens.qr.hint') }}</p>
            </div>
          </div>
        </div>
        <div v-else class="stack">
          <ul class="names">
            <li v-for="name in honeytoken.trigger_names" :key="name" class="row">
              <code class="mono value">{{ name }}</code>
              <CopyButton :value="name" />
            </li>
          </ul>
          <p class="hint">{{ t('honeytokens.place.fixed') }}</p>
        </div>
      </div>

      <div class="section panel">
        <dl class="definition">
          <dt>{{ t('field.notes') }}</dt>
          <dd class="notes">{{ honeytoken.notes === '' ? t('common.none') : honeytoken.notes }}</dd>
          <template v-if="honeytoken.type === 'web_url'">
            <dt>{{ t('honeytokens.redirect') }}</dt>
            <dd>{{ honeytoken.redirect_url ?? t('common.none') }}</dd>
          </template>
          <dt>{{ t('field.techniques') }}</dt>
          <dd class="mono">{{ honeytoken.techniques.length === 0 ? t('common.none') : honeytoken.techniques.join(', ') }}</dd>
          <dt>{{ t('field.scenario') }}</dt>
          <dd>
            <ScenarioAssignment
              kind="honeytoken"
              :resource-id="honeytoken.id"
              :scenario-id="honeytoken.scenario_id"
              :can-write="canWrite"
              @changed="(scenarioId) => honeytoken && (honeytoken = { ...honeytoken, scenario_id: scenarioId })"
            />
          </dd>
          <dt>{{ t('field.created') }}</dt>
          <dd><TimeStamp :value="honeytoken.created_at" /></dd>
          <dt>{{ t('field.updated') }}</dt>
          <dd><TimeStamp :value="honeytoken.updated_at" /></dd>
        </dl>
      </div>

      <div v-if="canWrite" class="section panel narrow">
        <h2>{{ t('honeytokens.change') }}</h2>
        <p v-if="saved" class="notice notice-ok" role="status">{{ t('common.saved') }}</p>
        <HoneytokenForm :key="honeytoken.updated_at" :existing="honeytoken" :busy="busy" :submit-label="t('common.save')" @update="update" />
      </div>

      <ConfirmDialog
        v-if="canWrite"
        :open="confirming"
        :title="t('honeytokens.delete.title')"
        :confirm="t('honeytokens.delete.confirm')"
        :busy="busy"
        @confirm="remove"
        @cancel="confirming = false"
      >
        {{ t('honeytokens.delete.body') }}
      </ConfirmDialog>
    </template>

    <p v-else-if="error" class="notice notice-error" role="alert">{{ error }}</p>
  </section>
</template>

<style scoped>
.badges {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
  margin-top: 0.5rem;
}

.place {
  display: flex;
  flex-wrap: wrap;
  gap: 1.5rem;
  align-items: flex-start;
  justify-content: space-between;
}

.place .stack {
  flex: 1 1 18rem;
}

.row {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  align-items: center;
}

.value {
  padding: 0.35rem 0.6rem;
  border-radius: var(--radius-sm);
  background: var(--ink);
  color: #e2e9e5;
  font-size: 0.8125rem;
  overflow-wrap: anywhere;
}

.names {
  display: grid;
  gap: 0.5rem;
  margin: 0;
  padding: 0;
  list-style: none;
}

.qr {
  display: grid;
  gap: 0.5rem;
  max-width: 14rem;
  justify-items: start;
}

.qr-code {
  display: grid;
  gap: 0.5rem;
}

.notes {
  white-space: pre-wrap;
}

.narrow {
  max-width: 36rem;
}
</style>
