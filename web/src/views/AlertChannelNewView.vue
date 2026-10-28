<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, ref } from 'vue';
import { useRouter } from 'vue-router';
import { api } from '../api/client';
import type { AlertChannel, CreateAlertChannelRequest } from '../api/generated';
import { errorText } from '../api/messages';
import AlertChannelTarget from '../components/AlertChannelTarget.vue';
import ConfirmWithPassword from '../components/ConfirmWithPassword.vue';
import { t } from '../i18n';
import { maxRecipients, parseRecipients } from '../recipients';

const router = useRouter();

const types = ['webhook', 'slack', 'teams', 'email'] as const;

const type = ref<AlertChannel['type']>('webhook');
// A webhook takes any receiver of JSON, so there is nothing to say about it.
const typeHint = computed(() => (type.value === 'webhook' ? undefined : t(`alertChannelType.${type.value}.hint`)));
const name = ref('');
const enabled = ref(true);
const url = ref('');
const headerName = ref('');
const headerValue = ref('');
const removeHeader = ref(false);
const recipients = ref('');
const confirming = ref(false);
const error = ref<string | undefined>();
let createdId: string | undefined;

const parsed = computed(() => parseRecipients(recipients.value));
const problem = computed(() => {
  // Spaces pass the required fields, and the server would refuse them without saying which field.
  if (name.value.trim() === '') {
    return t('field.nameRequired');
  }
  if (type.value !== 'email' && url.value.trim() === '') {
    return t('alerts.urlRequired');
  }
  if (type.value === 'email') {
    const { addresses, invalid, repeated } = parsed.value;
    if (invalid.length > 0 || repeated.length > 0 || addresses.length < 1 || addresses.length > maxRecipients) {
      return t('alerts.recipientsCount', { max: maxRecipients });
    }
    return undefined;
  }
  if (type.value === 'webhook' && (headerName.value.trim() === '') !== (headerValue.value === '')) {
    return t('alerts.headerBoth');
  }
  return undefined;
});
const shown = ref<string | undefined>();

function ask(): void {
  shown.value = problem.value;
  error.value = undefined;
  if (problem.value === undefined) {
    confirming.value = true;
  }
}

/** The password is added here and goes nowhere else: it is not kept with the form. */
async function create(password: string | undefined): Promise<void> {
  const body: CreateAlertChannelRequest = { name: name.value.trim(), type: type.value, enabled: enabled.value, password };
  if (type.value === 'email') {
    body.recipients = parsed.value.addresses;
  } else {
    body.url = url.value.trim();
    if (type.value === 'webhook' && headerValue.value !== '') {
      body.header = { name: headerName.value.trim(), value: headerValue.value };
    }
  }
  createdId = (await api.call('createAlertChannel', { body })).body.id;
}

async function created(): Promise<void> {
  confirming.value = false;
  if (createdId !== undefined) {
    await router.replace({ name: 'alert-channel', params: { id: createdId }, query: { created: '1' } });
  }
}
</script>

<template>
  <section>
    <p><RouterLink :to="{ name: 'alert-channels' }">{{ t('alerts.back') }}</RouterLink></p>
    <div class="page-head">
      <h1>{{ t('alerts.create.title') }}</h1>
    </div>

    <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>

    <form class="stack narrow" @submit.prevent="ask">
      <div class="field">
        <label for="channel-type">{{ t('field.type') }}</label>
        <select id="channel-type" v-model="type" :aria-describedby="typeHint === undefined ? undefined : 'channel-type-hint'">
          <option v-for="option in types" :key="option" :value="option">{{ t(`alertChannelType.${option}`) }}</option>
        </select>
        <span v-if="typeHint !== undefined" id="channel-type-hint" class="hint">{{ typeHint }}</span>
      </div>

      <div class="field">
        <label for="channel-name">{{ t('field.name') }}</label>
        <input id="channel-name" v-model="name" type="text" required maxlength="64" />
      </div>

      <AlertChannelTarget
        v-model:url="url"
        v-model:header-name="headerName"
        v-model:header-value="headerValue"
        v-model:remove-header="removeHeader"
        v-model:recipients="recipients"
        :type="type"
        url-required
      />

      <div class="field">
        <label class="check" for="channel-enabled"><input id="channel-enabled" v-model="enabled" type="checkbox" />{{ t('field.enabled') }}</label>
      </div>

      <p v-if="shown" class="notice notice-error" role="alert">{{ shown }}</p>

      <div class="actions-row">
        <button class="button button-primary" type="submit">{{ t('alerts.create.submit') }}</button>
      </div>
    </form>

    <ConfirmWithPassword
      :open="confirming"
      :title="t('alerts.create.confirmTitle')"
      :confirm="t('alerts.create.submit')"
      :action="create"
      @done="created"
      @cancel="confirming = false"
      @failed="(failure) => { confirming = false; error = errorText(failure); }"
    >
      {{ t('alerts.create.confirmBody') }}
    </ConfirmWithPassword>
  </section>
</template>

<style scoped>
.narrow {
  max-width: 36rem;
}
</style>
