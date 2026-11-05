<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed } from 'vue';
import { engageLabel, useEngageActivities } from '../engageNames';
import { t } from '../i18n';

// The activities of the scenario, in the order of the list. A native group of checkboxes: the browser brings the
// keyboard, the labels and the announcements, and the list is short enough to need no search.
const chosen = defineModel<string[]>({ required: true });

const { activities, names, loaded, failed, load } = useEngageActivities();

// An identifier that the list lacks, such as one from a newer version of Engage or any while the names are not read,
// stays in the group under its identifier instead of going without a word when the scenario is saved.
const rows = computed(() => {
  const known = new Set(activities.value.map((a) => a.id));
  const unknown = chosen.value.filter((id) => !known.has(id));
  return [...activities.value.map((a) => a.id), ...unknown];
});

function toggle(id: string, on: boolean): void {
  const next = on ? [...chosen.value, id] : chosen.value.filter((value) => value !== id);
  const order = rows.value;
  chosen.value = order.filter((value) => next.includes(value));
}
</script>

<template>
  <fieldset class="group" aria-describedby="engage-hint">
    <legend>{{ t('scenarios.engage') }}</legend>
    <p id="engage-hint" class="hint">{{ t('scenarios.engageHint') }}</p>
    <div v-if="failed" class="notice notice-error" role="alert">
      {{ t('scenarios.engageLoadFailed') }}
      <button class="button button-ghost small" type="button" @click="load">{{ t('scenarios.stories.retry') }}</button>
    </div>
    <p v-else-if="!loaded" role="status" class="hint">{{ t('app.loading') }}</p>
    <div class="list">
      <label v-for="id in rows" :key="id" class="check">
        <input type="checkbox" :checked="chosen.includes(id)" @change="toggle(id, ($event.target as HTMLInputElement).checked)" />
        <bdi>{{ engageLabel(id, names) }}</bdi>
      </label>
    </div>
  </fieldset>
</template>

<style scoped>
.group {
  margin: 0;
  padding: 0.5rem 0.75rem 0.75rem;
  border: 1px solid var(--line);
  border-radius: var(--radius-sm);
}

.group legend {
  padding: 0 0.3rem;
  font-weight: 600;
}

.hint {
  margin: 0 0 0.5rem;
  color: var(--slate);
  font-size: 0.8125rem;
}

.list {
  display: grid;
  gap: 0.3rem;
}

.check {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}
</style>
