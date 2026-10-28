<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed } from 'vue';
import { saveFile } from '../download';
import { t } from '../i18n';
import CopyButton from './CopyButton.vue';

// Recovery codes are shown once. The page that got them holds them, and the user
// copies or saves them from here: they are in no store, no address and no history.
const props = defineProps<{ codes: readonly string[] }>();
defineEmits<{ done: [] }>();

const text = computed(() => `${props.codes.join('\n')}\n`);

function download(): void {
  saveFile(new Blob([text.value], { type: 'text/plain' }), 'nyktus-recovery-codes.txt');
}
</script>

<template>
  <div class="section panel" role="region" :aria-label="t('account.codes.title')">
    <h2>{{ t('account.codes.title') }}</h2>
    <ul class="codes mono">
      <li v-for="code in codes" :key="code">{{ code }}</li>
    </ul>
    <div class="actions-row">
      <CopyButton :value="text" />
      <button class="button button-ghost small" type="button" @click="download">{{ t('account.codes.download') }}</button>
    </div>
    <div class="actions-row">
      <button class="button button-primary" type="button" @click="$emit('done')">{{ t('account.codes.done') }}</button>
    </div>
  </div>
</template>

<style scoped>
.codes {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(14rem, 1fr));
  gap: 0.4rem 1.5rem;
  margin: 0;
  padding: 0.75rem 1rem;
  border-radius: var(--radius-sm);
  background: var(--ink);
  color: #e2e9e5;
  font-size: 0.875rem;
  list-style: none;
}
</style>
