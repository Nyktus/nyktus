<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { t } from '../i18n';
import type { CatalogDeception } from '../api/generated';

// The files that a deception recommends, all chosen at first. Taking one away only leaves it
// out of what is created now; it can be added to the scenario later.
defineProps<{
  artifacts: CatalogDeception['artifacts'];
  hint: string;
}>();

const selected = defineModel<string[]>({ required: true });
</script>

<template>
  <fieldset v-if="artifacts.length > 0" class="files">
    <legend>{{ t('catalog.apply.files') }}</legend>
    <p class="hint">{{ hint }}</p>
    <div v-for="artifact in artifacts" :key="artifact.key" class="field">
      <label class="check">
        <input v-model="selected" type="checkbox" :value="artifact.key" />
        <span><bdi class="mono">{{ artifact.file_name }}</bdi> <span class="hint">{{ t(`artifactFormat.${artifact.format}`) }}</span></span>
      </label>
    </div>
    <p v-if="selected.length === 0" class="hint">{{ t('catalog.apply.noFiles') }}</p>
  </fieldset>
</template>

<style scoped>
.hint {
  color: var(--slate);
  font-size: 0.8125rem;
}

.files {
  display: grid;
  gap: 0.6rem;
  margin: 0;
  padding: 0.9rem;
  border: 1px solid var(--line);
  border-radius: var(--radius-sm);
}

.files legend {
  padding: 0 0.3rem;
  font-weight: 600;
}
</style>
