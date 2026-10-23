<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { t } from '../i18n';
import CopyButton from './CopyButton.vue';

// The key is shown once. The page that got it holds it, and the user copies it from
// here: it is in no store, no address and no history.
defineProps<{ secret: string }>();
defineEmits<{ done: [] }>();
</script>

<template>
  <div class="section panel" role="region" :aria-label="t('apiKeys.reveal.title')">
    <h2>{{ t('apiKeys.reveal.title') }}</h2>
    <p class="notice" role="status">{{ t('apiKeys.reveal.warning') }}</p>
    <div class="row">
      <code class="mono value">{{ secret }}</code>
      <CopyButton :value="secret" />
    </div>
    <div class="actions-row">
      <button class="button button-primary" type="button" @click="$emit('done')">{{ t('apiKeys.reveal.done') }}</button>
    </div>
  </div>
</template>

<style scoped>
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
</style>
