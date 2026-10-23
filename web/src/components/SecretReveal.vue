<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { t } from '../i18n';
import CopyButton from './CopyButton.vue';

defineProps<{ secret: string; config: string }>();
defineEmits<{ done: [] }>();
</script>

<template>
  <div class="section panel reveal" role="region" :aria-label="t('secret.title')">
    <h2>{{ t('secret.title') }}</h2>
    <p class="notice" role="status">{{ t('secret.warning') }}</p>
    <div class="stack">
      <div>
        <p class="label">{{ t('secret.secret') }}</p>
        <div class="row">
          <code class="mono value">{{ secret }}</code>
          <CopyButton :value="secret" />
        </div>
      </div>
      <div>
        <p class="label">{{ t('secret.config') }}</p>
        <pre class="mono value config">{{ config }}</pre>
        <CopyButton :value="config" />
      </div>
      <div class="actions-row">
        <button class="button button-primary" type="button" @click="$emit('done')">{{ t('secret.done') }}</button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.label {
  margin-bottom: 0.35rem;
  font-size: 0.8125rem;
  font-weight: 600;
}

.row {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  align-items: center;
}

.value {
  padding: 0.5rem 0.7rem;
  border-radius: var(--radius-sm);
  background: var(--ink);
  color: #e2e9e5;
  font-size: 0.8125rem;
  overflow-wrap: anywhere;
}

.config {
  margin: 0 0 0.5rem;
  white-space: pre-wrap;
}
</style>
