<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed } from 'vue';
import type { AlertChannel } from '../api/generated';
import { t } from '../i18n';
import { parseRecipients } from '../recipients';

// The fields that say where a channel sends its alerts. The URL and the value of a
// header are secrets: this form can write them and never shows them, and the page
// that holds it empties them once a change has been made. `type` is fixed by the
// page; a form that creates a channel has a choice of its own above this one.
defineProps<{ type: AlertChannel['type']; currentHeader?: string | null; urlRequired?: boolean }>();

const url = defineModel<string>('url', { required: true });
const headerName = defineModel<string>('headerName', { required: true });
const headerValue = defineModel<string>('headerValue', { required: true });
const removeHeader = defineModel<boolean>('removeHeader', { default: false });
const recipients = defineModel<string>('recipients', { required: true });

const parsed = computed(() => parseRecipients(recipients.value));
</script>

<template>
  <template v-if="type !== 'email'">
    <div class="field">
      <label for="channel-url">{{ t('alerts.url') }}</label>
      <input
        id="channel-url"
        v-model="url"
        type="url"
        maxlength="2048"
        autocomplete="off"
        spellcheck="false"
        aria-describedby="channel-url-hint"
        :required="urlRequired"
      />
      <span id="channel-url-hint" class="hint">{{ t(`alerts.urlHint.${type}`) }}</span>
    </div>

    <template v-if="type === 'webhook'">
      <p v-if="currentHeader" class="hint">{{ t('alerts.headerCurrent', { name: currentHeader }) }}</p>
      <div class="field">
        <label for="channel-header-name">{{ t('alerts.headerName') }}</label>
        <input id="channel-header-name" v-model="headerName" type="text" maxlength="128" autocomplete="off" spellcheck="false" :disabled="removeHeader" />
      </div>
      <div class="field">
        <label for="channel-header-value">{{ t('alerts.headerValue') }}</label>
        <input
          id="channel-header-value"
          v-model="headerValue"
          type="password"
          maxlength="1024"
          autocomplete="off"
          spellcheck="false"
          aria-describedby="channel-header-hint"
          :disabled="removeHeader"
        />
        <span id="channel-header-hint" class="hint">{{ t('alerts.headerHint') }}</span>
      </div>
      <div v-if="currentHeader" class="field">
        <label class="check" for="channel-header-remove"><input id="channel-header-remove" v-model="removeHeader" type="checkbox" />{{ t('alerts.removeHeader') }}</label>
      </div>
    </template>
  </template>

  <div v-else class="field">
    <label for="channel-recipients">{{ t('alerts.recipients') }}</label>
    <textarea id="channel-recipients" v-model="recipients" autocomplete="off" spellcheck="false" aria-describedby="channel-recipients-hint"></textarea>
    <span id="channel-recipients-hint" class="hint">{{ t('alerts.recipientsHint') }}</span>
    <span v-if="parsed.invalid.length > 0" class="hint problem" role="alert">{{ t('alerts.recipientsInvalid', { values: parsed.invalid.join(', ') }) }}</span>
    <span v-if="parsed.repeated.length > 0" class="hint problem" role="alert">{{ t('alerts.recipientsRepeated', { values: parsed.repeated.join(', ') }) }}</span>
  </div>
</template>

<style scoped>
.problem {
  color: var(--danger);
}
</style>
