<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { ApiError } from '../api/errors';
import type { Scenario } from '../api/generated';
import { errorText } from '../api/messages';
import { t } from '../i18n';
import { loadScenarioChoices } from '../scenarioChoices';

const props = defineProps<{
  /** The scenario that a link names. It is chosen only once the list holds it, so that nothing is sent that the person cannot see. */
  preselected?: string;
}>();

// The scenario that a new resource joins when it is created; empty for none.
const chosen = defineModel<string>({ required: true });

const choices = ref<Scenario[]>([]);
const truncated = ref(false);
const loaded = ref(false);
const error = ref<string | undefined>();

onMounted(async () => {
  try {
    const result = await loadScenarioChoices();
    choices.value = result.scenarios;
    truncated.value = result.truncated;
    loaded.value = true;
    // The list is not shown before it is loaded, so the person has chosen nothing yet.
    if (result.scenarios.some((s) => s.id === props.preselected)) {
      chosen.value = props.preselected ?? '';
    }
  } catch (failure) {
    error.value = errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
  }
});
</script>

<template>
  <div class="field">
    <template v-if="loaded && choices.length > 0">
      <label for="scenario">{{ t('scenarioSelect.label') }}</label>
      <select id="scenario" v-model="chosen" aria-describedby="scenario-hint">
        <option value="">{{ t('scenarioSelect.none') }}</option>
        <option v-for="scenario in choices" :key="scenario.id" :value="scenario.id">{{ scenario.name }}</option>
      </select>
      <span id="scenario-hint" class="hint">{{ t('scenarioAssign.hint') }}</span>
      <span v-if="truncated" class="hint">{{ t('scenarioAssign.truncated', { count: choices.length }) }}</span>
    </template>
    <p v-else-if="error" class="notice notice-error" role="alert">{{ error }}</p>
  </div>
</template>
