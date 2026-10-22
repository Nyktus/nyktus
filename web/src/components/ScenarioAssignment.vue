<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { onMounted, ref, watch } from 'vue';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { Scenario } from '../api/generated';
import { errorText } from '../api/messages';
import { t } from '../i18n';

const props = defineProps<{
  kind: 'honeytoken' | 'honeypot';
  resourceId: string;
  /** The scenario that the resource belongs to now, or null. */
  scenarioId: string | null;
  canWrite: boolean;
}>();

const emit = defineEmits<{ changed: [scenarioId: string | null] }>();

const current = ref<Scenario | undefined>();
const choices = ref<Scenario[]>([]);
const chosen = ref('');
const busy = ref(false);
const error = ref<string | undefined>();
const choicesLoaded = ref(false);
const truncated = ref(false);

/** The most pages of scenarios that the picker reads, so that it cannot loop without end. */
const maxPages = 10;

function show(failure: unknown): string {
  return errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
}

// The scenario that was asked for last is the one that is shown, whatever the order of the answers.
let asked = 0;

async function loadCurrent(): Promise<void> {
  const mine = ++asked;
  current.value = undefined;
  if (props.scenarioId === null) {
    return;
  }
  try {
    const body = (await api.call('getScenario', { path: { id: props.scenarioId } })).body;
    if (mine === asked) {
      current.value = body;
    }
  } catch {
    // The page shows the resource without the name of its scenario.
  }
}

async function loadChoices(): Promise<void> {
  const all: Scenario[] = [];
  let cursor: string | undefined;
  try {
    for (let page = 0; page < maxPages; page++) {
      const { body } = await api.call('listScenarios', { query: { limit: 200, cursor } });
      all.push(...body.scenarios);
      cursor = body.next_cursor;
      if (cursor === undefined) {
        break;
      }
    }
    choices.value = all;
    truncated.value = cursor !== undefined;
    choicesLoaded.value = true;
  } catch (failure) {
    error.value = show(failure);
  }
}

async function assign(): Promise<void> {
  if (chosen.value === '') {
    return;
  }
  busy.value = true;
  error.value = undefined;
  try {
    const body = { scenario_id: chosen.value };
    if (props.kind === 'honeytoken') {
      await api.call('assignHoneytokenScenario', { path: { id: props.resourceId }, body });
    } else {
      await api.call('assignHoneypotScenario', { path: { id: props.resourceId }, body });
    }
    chosen.value = '';
    emit('changed', body.scenario_id);
  } catch (failure) {
    error.value = show(failure);
  } finally {
    busy.value = false;
  }
}

async function remove(): Promise<void> {
  busy.value = true;
  error.value = undefined;
  try {
    if (props.kind === 'honeytoken') {
      await api.call('detachHoneytokenScenario', { path: { id: props.resourceId } });
    } else {
      await api.call('detachHoneypotScenario', { path: { id: props.resourceId } });
    }
    emit('changed', null);
  } catch (failure) {
    error.value = show(failure);
  } finally {
    busy.value = false;
  }
}

onMounted(async () => {
  await loadCurrent();
  if (props.canWrite && props.scenarioId === null) {
    await loadChoices();
  }
});
watch(
  () => props.scenarioId,
  async (id) => {
    await loadCurrent();
    if (props.canWrite && id === null && choices.value.length === 0) {
      await loadChoices();
    }
  },
);
</script>

<template>
  <div class="assign">
    <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>
    <template v-if="scenarioId !== null">
      <p>
        <RouterLink v-if="current" :to="{ name: 'scenario', params: { id: scenarioId } }">{{ current.name }}</RouterLink>
        <template v-else>{{ scenarioId }}</template>
      </p>
      <button v-if="canWrite" class="button button-ghost small" type="button" :disabled="busy" @click="remove">
        {{ t('scenarioAssign.remove') }}
      </button>
    </template>
    <template v-else>
      <p>{{ t('scenarioAssign.none') }}</p>
      <form v-if="canWrite && choices.length > 0" class="assign-form" @submit.prevent="assign">
        <label class="visually-hidden" :for="`scenario-${kind}`">{{ t('scenarioAssign.choose') }}</label>
        <select :id="`scenario-${kind}`" v-model="chosen">
          <option value="">{{ t('scenarioAssign.choose') }}</option>
          <option v-for="scenario in choices" :key="scenario.id" :value="scenario.id">{{ scenario.name }}</option>
        </select>
        <button class="button button-ghost small" type="submit" :disabled="busy || chosen === ''">{{ t('scenarioAssign.assign') }}</button>
      </form>
      <p v-if="canWrite && choices.length > 0" class="hint">{{ t('scenarioAssign.hint') }}</p>
      <p v-else-if="canWrite && choicesLoaded" class="hint">{{ t('scenarioAssign.noScenarios') }}</p>
      <p v-if="truncated" class="hint">{{ t('scenarioAssign.truncated', { count: choices.length }) }}</p>
    </template>
  </div>
</template>

<style scoped>
.assign {
  display: grid;
  gap: 0.5rem;
  justify-items: start;
}

.assign-form {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.assign-form select {
  min-height: 2rem;
  padding: 0.2rem 0.5rem;
  border: 1px solid var(--field-border);
  border-radius: var(--radius-sm);
  background: var(--surface-raised);
  color: var(--ink);
  font: inherit;
}

.hint {
  color: var(--slate);
  font-size: 0.8125rem;
}
</style>
