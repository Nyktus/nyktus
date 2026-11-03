<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { Honeypot, OperationTypes } from '../api/generated';
import { errorText } from '../api/messages';
import ConfirmDialog from '../components/ConfirmDialog.vue';
import HoneypotForm from '../components/HoneypotForm.vue';
import HoneypotStatusBadge from '../components/HoneypotStatusBadge.vue';
import ScenarioAssignment from '../components/ScenarioAssignment.vue';
import SecretReveal from '../components/SecretReveal.vue';
import SeverityBadge from '../components/SeverityBadge.vue';
import StateBadge from '../components/StateBadge.vue';
import TimeStamp from '../components/TimeStamp.vue';
import { t } from '../i18n';
import { session } from '../session';

const route = useRoute();
const router = useRouter();

const id = computed(() => String(route.params.id));
const honeypot = ref<Honeypot | undefined>();
const loading = ref(true);
const missing = ref(false);
const error = ref<string | undefined>();
const saved = ref(false);
const busy = ref(false);
const deleting = ref(false);
const replacing = ref(false);
// The secret is held by this page only while it is shown: it is in no store, no address and no history.
const revealed = ref<{ secret: string; config: string } | undefined>();
const canWrite = computed(() => session.can('honeypots:write'));

function show(failure: unknown): string {
  return errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
}

function discard(): void {
  revealed.value = undefined;
}

async function load(): Promise<void> {
  loading.value = true;
  error.value = undefined;
  try {
    honeypot.value = (await api.call('getHoneypot', { path: { id: id.value } })).body;
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

async function update(body: OperationTypes['updateHoneypot']['body']): Promise<void> {
  error.value = undefined;
  saved.value = false;
  if (Object.keys(body).length === 0) {
    saved.value = true;
    return;
  }
  busy.value = true;
  try {
    honeypot.value = (await api.call('updateHoneypot', { path: { id: id.value }, body })).body;
    saved.value = true;
  } catch (failure) {
    error.value = show(failure);
  } finally {
    busy.value = false;
  }
}

async function showSecret(): Promise<void> {
  busy.value = true;
  error.value = undefined;
  try {
    const { secret, sensor_config: config } = (await api.call('getHoneypotSecret', { path: { id: id.value } })).body;
    revealed.value = { secret, config };
  } catch (failure) {
    error.value = show(failure);
  } finally {
    busy.value = false;
  }
}

async function replaceSecret(): Promise<void> {
  busy.value = true;
  error.value = undefined;
  try {
    const { secret, sensor_config: config, ...rest } = (await api.call('replaceHoneypotSecret', { path: { id: id.value } })).body;
    honeypot.value = rest;
    revealed.value = { secret, config };
  } catch (failure) {
    error.value = show(failure);
  } finally {
    replacing.value = false;
    busy.value = false;
  }
}

async function remove(): Promise<void> {
  busy.value = true;
  try {
    await api.call('deleteHoneypot', { path: { id: id.value } });
    await router.replace({ name: 'honeypots' });
  } catch (failure) {
    deleting.value = false;
    error.value = show(failure);
  } finally {
    busy.value = false;
  }
}

onMounted(load);
onBeforeUnmount(discard);
</script>

<template>
  <section>
    <p><RouterLink :to="{ name: 'honeypots' }">{{ t('honeypots.back') }}</RouterLink></p>

    <p v-if="loading" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="missing" class="notice" role="status">{{ t('error.not_found') }}</p>

    <template v-else-if="honeypot">
      <div class="page-head">
        <div>
          <h1>{{ honeypot.name }}</h1>
          <p class="badges">
            <StateBadge :enabled="honeypot.enabled" />
            <HoneypotStatusBadge :status="honeypot.status" />
            <SeverityBadge :severity="honeypot.severity" />
            <span class="badge">{{ t(`honeypotService.${honeypot.service}`) }}</span>
          </p>
        </div>
        <div v-if="canWrite" class="actions-row">
          <button v-if="!revealed" class="button button-ghost" type="button" :disabled="busy" @click="showSecret">{{ t('secret.show') }}</button>
          <button class="button button-ghost" type="button" @click="replacing = true">{{ t('secret.replace') }}</button>
          <button class="button button-ghost" type="button" @click="deleting = true">{{ t('common.delete') }}</button>
        </div>
      </div>

      <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>
      <SecretReveal v-if="revealed" :secret="revealed.secret" :config="revealed.config" @done="discard" />

      <div class="section panel">
        <dl class="definition">
          <dt>{{ t('field.notes') }}</dt>
          <dd class="notes">{{ honeypot.notes === '' ? t('common.none') : honeypot.notes }}</dd>
          <dt>{{ t('honeypots.lastSeen') }}</dt>
          <dd>
            <TimeStamp v-if="honeypot.last_seen_at" :value="honeypot.last_seen_at" />
            <template v-else>{{ t('honeypots.never') }}</template>
          </dd>
          <dt>{{ t('honeypots.sensorVersion') }}</dt>
          <dd class="mono">{{ honeypot.sensor_version ?? t('common.none') }}</dd>
          <dt>{{ t('field.techniques') }}</dt>
          <dd class="mono">{{ honeypot.techniques.length === 0 ? t('common.none') : honeypot.techniques.join(', ') }}</dd>
          <dt>{{ t('field.scenario') }}</dt>
          <dd>
            <ScenarioAssignment
              kind="honeypot"
              :resource-id="honeypot.id"
              :scenario-id="honeypot.scenario_id"
              :can-write="canWrite"
              @changed="(scenarioId) => honeypot && (honeypot = { ...honeypot, scenario_id: scenarioId })"
            />
          </dd>
          <dt>{{ t('field.created') }}</dt>
          <dd><TimeStamp :value="honeypot.created_at" /></dd>
          <dt>{{ t('field.updated') }}</dt>
          <dd><TimeStamp :value="honeypot.updated_at" /></dd>
        </dl>
      </div>

      <div v-if="canWrite" class="section panel narrow">
        <h2>{{ t('honeypots.change') }}</h2>
        <p v-if="saved" class="notice notice-ok" role="status">{{ t('common.saved') }}</p>
        <HoneypotForm :key="honeypot.updated_at" :existing="honeypot" :busy="busy" :submit-label="t('common.save')" @update="update" />
      </div>

      <ConfirmDialog
        v-if="canWrite"
        :open="replacing"
        :title="t('secret.replace.title')"
        :confirm="t('secret.replace.confirm')"
        :busy="busy"
        @confirm="replaceSecret"
        @cancel="replacing = false"
      >
        {{ t('secret.replace.body') }}
      </ConfirmDialog>
      <ConfirmDialog
        v-if="canWrite"
        :open="deleting"
        :title="t('honeypots.delete.title')"
        :confirm="t('honeypots.delete.confirm')"
        :busy="busy"
        @confirm="remove"
        @cancel="deleting = false"
      >
        {{ t('honeypots.delete.body') }}
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

.notes {
  white-space: pre-wrap;
}

.narrow {
  max-width: 36rem;
}
</style>
