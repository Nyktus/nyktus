<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { AlertChannel, AlertDelivery, UpdateAlertChannelRequest } from '../api/generated';
import { errorText } from '../api/messages';
import AlertChannelTarget from '../components/AlertChannelTarget.vue';
import ConfirmDialog from '../components/ConfirmDialog.vue';
import ConfirmWithPassword from '../components/ConfirmWithPassword.vue';
import StateBadge from '../components/StateBadge.vue';
import TimeStamp from '../components/TimeStamp.vue';
import { t } from '../i18n';
import { maxRecipients, parseRecipients } from '../recipients';
import { session } from '../session';

/** How often the outcome of a test is asked for, in milliseconds, and how many times. */
const pollEvery = 2000;
const pollTimes = 15;

const route = useRoute();
const router = useRouter();

const id = computed(() => String(route.params.id));
const channel = ref<AlertChannel | undefined>();
const loading = ref(true);
const missing = ref(false);
const error = ref<string | undefined>();
const saved = ref(false);
const busy = ref(false);
const deleting = ref(false);
const created = computed(() => route.query.created === '1');
const canWrite = computed(() => session.can('alert_channels:write'));

const name = ref('');
const url = ref('');
const headerName = ref('');
const headerValue = ref('');
const removeHeader = ref(false);
const recipients = ref('');
const targetProblem = ref<string | undefined>();

/** The change that waits for the password of the user. */
const confirmation = ref<{ title: string; body: UpdateAlertChannelRequest } | undefined>();

function show(failure: unknown): string {
  return errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
}

/** Shows what the server holds. The fields of the forms are set by the actions that they belong to, so that a change of one does not discard what was typed into another. */
function adopt(from: AlertChannel): void {
  channel.value = from;
}

function fillForms(from: AlertChannel): void {
  name.value = from.name;
  recipients.value = (from.recipients ?? []).join('\n');
}

/** The note that the channel was just created belongs to the first thing that is done with it. */
function forgetCreated(): void {
  if (created.value) {
    void router.replace({ name: route.name ?? 'alert-channel', params: route.params });
  }
}

function clearSecrets(): void {
  url.value = '';
  headerName.value = '';
  headerValue.value = '';
  removeHeader.value = false;
}

async function load(): Promise<void> {
  try {
    const loaded = (await api.call('getAlertChannel', { path: { id: id.value } })).body;
    adopt(loaded);
    fillForms(loaded);
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

async function rename(): Promise<void> {
  const current = channel.value;
  const next = name.value.trim();
  error.value = undefined;
  saved.value = false;
  if (next === '') {
    error.value = t('field.nameRequired');
    return;
  }
  if (current === undefined || next === current.name) {
    saved.value = true;
    return;
  }
  busy.value = true;
  try {
    // A new name decides nothing about where alerts go, so it needs no password.
    const renamed = (await api.call('updateAlertChannel', { path: { id: id.value }, body: { name: next } })).body;
    adopt(renamed);
    name.value = renamed.name;
    saved.value = true;
    forgetCreated();
  } catch (failure) {
    error.value = show(failure);
  } finally {
    busy.value = false;
  }
}

function askState(enabled: boolean): void {
  error.value = undefined;
  saved.value = false;
  confirmation.value = { title: enabled ? t('alerts.enable.title') : t('alerts.disable.title'), body: { enabled } };
}

function askTarget(): void {
  const current = channel.value;
  error.value = undefined;
  saved.value = false;
  targetProblem.value = undefined;
  if (current === undefined) {
    return;
  }
  const body: UpdateAlertChannelRequest = {};
  if (current.type === 'email') {
    const { addresses, invalid, repeated } = parseRecipients(recipients.value);
    if (invalid.length > 0 || repeated.length > 0 || addresses.length < 1 || addresses.length > maxRecipients) {
      targetProblem.value = t('alerts.recipientsCount', { max: maxRecipients });
      return;
    }
    if (addresses.join('\n') !== (current.recipients ?? []).join('\n')) {
      body.recipients = addresses;
    }
  } else {
    if (url.value.trim() !== '') {
      body.url = url.value.trim();
    }
    if (current.type === 'webhook') {
      if (removeHeader.value) {
        body.header = null;
      } else if (headerName.value.trim() !== '' || headerValue.value !== '') {
        if (headerName.value.trim() === '' || headerValue.value === '') {
          targetProblem.value = t('alerts.headerBoth');
          return;
        }
        body.header = { name: headerName.value.trim(), value: headerValue.value };
      }
    }
  }
  if (Object.keys(body).length === 0) {
    targetProblem.value = t('alerts.nothing');
    return;
  }
  confirmation.value = { title: t('alerts.replace.title'), body };
}

/** Sends the change with the password; the page does not keep the password. */
async function confirmed(password: string | undefined): Promise<void> {
  const pending = confirmation.value;
  if (pending === undefined) {
    return;
  }
  const changed = (await api.call('updateAlertChannel', { path: { id: id.value }, body: { ...pending.body, password } })).body;
  adopt(changed);
  if (pending.body.recipients !== undefined) {
    recipients.value = (changed.recipients ?? []).join('\n');
  }
}

function changed(): void {
  // The secrets are written; the form does not keep them.
  clearSecrets();
  confirmation.value = undefined;
  saved.value = true;
  forgetCreated();
}

function refused(failure: ApiError): void {
  confirmation.value = undefined;
  error.value = errorText(failure);
}

async function remove(): Promise<void> {
  busy.value = true;
  try {
    await api.call('deleteAlertChannel', { path: { id: id.value } });
    await router.replace({ name: 'alert-channels' });
  } catch (failure) {
    deleting.value = false;
    error.value = show(failure);
  } finally {
    busy.value = false;
  }
}

const delivery = ref<AlertDelivery | undefined>();
const testError = ref<string | undefined>();
const waiting = ref(false);
let timer: ReturnType<typeof setInterval> | undefined;
let asked = 0;
let gone = false;

function stop(): void {
  clearInterval(timer);
  timer = undefined;
  waiting.value = false;
}

async function check(): Promise<void> {
  const current = delivery.value;
  if (current === undefined) {
    return;
  }
  asked++;
  try {
    delivery.value = (await api.call('getAlertDelivery', { path: { id: current.id } })).body;
  } catch (failure) {
    testError.value = show(failure);
    stop();
    return;
  }
  if (delivery.value.status !== 'pending' || asked >= pollTimes) {
    stop();
  }
}

async function sendTest(): Promise<void> {
  testError.value = undefined;
  delivery.value = undefined;
  busy.value = true;
  try {
    delivery.value = (await api.call('testAlertChannel', { path: { id: id.value } })).body;
    if (gone) {
      return;
    }
    asked = 0;
    waiting.value = true;
    timer = setInterval(() => void check(), pollEvery);
  } catch (failure) {
    testError.value = show(failure);
  } finally {
    busy.value = false;
  }
}

async function checkAgain(): Promise<void> {
  asked = 0;
  await check();
}

onMounted(load);
onBeforeUnmount(() => {
  gone = true;
  stop();
});
</script>

<template>
  <section>
    <p><RouterLink :to="{ name: 'alert-channels' }">{{ t('alerts.back') }}</RouterLink></p>

    <p v-if="loading" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="missing" class="notice" role="status">{{ t('error.not_found') }}</p>

    <template v-else-if="channel">
      <div class="page-head">
        <div>
          <h1>{{ channel.name }}</h1>
          <p class="badges">
            <StateBadge :enabled="channel.enabled" />
            <span class="badge">{{ t(`alertChannelType.${channel.type}`) }}</span>
          </p>
        </div>
        <div v-if="canWrite" class="actions-row">
          <button v-if="channel.enabled" class="button button-ghost" type="button" @click="askState(false)">{{ t('alerts.disable') }}</button>
          <button v-else class="button button-primary" type="button" @click="askState(true)">{{ t('alerts.enable') }}</button>
        </div>
      </div>

      <p v-if="created" class="notice notice-ok" role="status">{{ t('alerts.created') }}</p>
      <p v-if="saved" class="notice notice-ok" role="status">{{ t('common.saved') }}</p>
      <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>

      <div class="section panel">
        <dl class="definition">
          <template v-if="channel.recipients !== null">
            <dt>{{ t('alerts.recipients') }}</dt>
            <dd class="mono">{{ channel.recipients.join(', ') }}</dd>
          </template>
          <template v-else>
            <dt>{{ t('alerts.target') }}</dt>
            <dd class="mono">{{ channel.target ?? t('common.none') }}</dd>
            <template v-if="channel.type === 'webhook'">
              <dt>{{ t('alerts.header') }}</dt>
              <dd class="mono">{{ channel.header_name ?? t('common.none') }}</dd>
            </template>
            <dt>{{ t('alerts.secret') }}</dt>
            <dd>{{ t('alerts.secretNote') }}</dd>
          </template>
          <dt>{{ t('field.created') }}</dt>
          <dd><TimeStamp :value="channel.created_at" /></dd>
          <dt>{{ t('field.updated') }}</dt>
          <dd><TimeStamp :value="channel.updated_at" /></dd>
        </dl>
      </div>

      <template v-if="canWrite">
        <div class="section panel narrow">
          <h2>{{ t('alerts.rename') }}</h2>
          <form class="stack" @submit.prevent="rename">
            <div class="field">
              <label for="channel-name">{{ t('field.name') }}</label>
              <input id="channel-name" v-model="name" type="text" required maxlength="64" aria-describedby="channel-name-hint" />
              <span id="channel-name-hint" class="hint">{{ t('alerts.renameHint') }}</span>
            </div>
            <div class="actions-row">
              <button class="button button-primary" type="submit" :disabled="busy">{{ busy ? t('app.saving') : t('common.save') }}</button>
            </div>
          </form>
        </div>

        <div class="section panel narrow">
          <h2>{{ t('alerts.replace.title') }}</h2>
          <p class="hint">{{ t('alerts.replaceHint') }}</p>
          <form class="stack" @submit.prevent="askTarget">
            <AlertChannelTarget
              v-model:url="url"
              v-model:header-name="headerName"
              v-model:header-value="headerValue"
              v-model:remove-header="removeHeader"
              v-model:recipients="recipients"
              :type="channel.type"
              :current-header="channel.header_name"
            />
            <p v-if="targetProblem" class="notice notice-error" role="alert">{{ targetProblem }}</p>
            <div class="actions-row">
              <button class="button button-primary" type="submit">{{ t('alerts.replace.submit') }}</button>
            </div>
          </form>
        </div>

        <div class="section panel narrow">
          <h2>{{ t('alerts.test.title') }}</h2>
          <p class="hint">{{ t('alerts.test.hint') }}</p>
          <div class="actions-row">
            <button class="button button-ghost" type="button" :disabled="busy || waiting" @click="sendTest">{{ t('alerts.test.send') }}</button>
          </div>
          <p v-if="testError" class="notice notice-error" role="alert">{{ testError }}</p>
          <div v-if="delivery" role="status">
            <p v-if="delivery.status === 'delivered'" class="notice notice-ok">{{ t('alerts.test.delivered') }}</p>
            <p v-else-if="delivery.status === 'dead'" class="notice notice-error">
              {{ t('alerts.test.dead', { reason: delivery.last_error === null ? t('common.none') : t(`deliveryError.${delivery.last_error}`) }) }}
              <template v-if="delivery.last_status_code !== null"> {{ t('deliveries.code', { code: delivery.last_status_code }) }}</template>
            </p>
            <p v-else-if="delivery.status === 'canceled'" class="notice">{{ t('alerts.test.canceled') }}</p>
            <p v-else-if="waiting" class="notice">{{ t('alerts.test.waiting') }}</p>
            <p v-else class="notice">
              {{ t('alerts.test.pending') }}
              <button class="button button-ghost" type="button" @click="checkAgain">{{ t('alerts.test.check') }}</button>
            </p>
          </div>
        </div>

        <div class="section panel narrow">
          <h2>{{ t('common.delete') }}</h2>
          <p class="hint">{{ channel.enabled ? t('alerts.delete.disableFirst') : t('alerts.delete.body') }}</p>
          <div class="actions-row">
            <button class="button button-ghost" type="button" :disabled="channel.enabled" @click="deleting = true">{{ t('alerts.delete.confirm') }}</button>
          </div>
        </div>

        <ConfirmWithPassword
          :open="confirmation !== undefined"
          :title="confirmation?.title ?? ''"
          :confirm="t('alerts.confirm')"
          :action="confirmed"
          @done="changed"
          @cancel="confirmation = undefined"
          @failed="refused"
        >
          {{ confirmation?.body.enabled === true ? t('alerts.enable.body') : confirmation?.body.enabled === false ? t('alerts.disable.body') : t('alerts.replace.body') }}
        </ConfirmWithPassword>

        <ConfirmDialog
          :open="deleting"
          :title="t('alerts.delete.title')"
          :confirm="t('alerts.delete.confirm')"
          :busy="busy"
          @confirm="remove"
          @cancel="deleting = false"
        >
          {{ t('alerts.delete.body') }}
        </ConfirmDialog>
      </template>
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

.narrow {
  max-width: 36rem;
}
</style>
