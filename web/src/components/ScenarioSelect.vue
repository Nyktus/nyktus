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

// The scenario that a new resource joins when it is created; empty for none. The scenario that
// the page asked for is kept only if the list holds it, so that nothing is sent that the person
// cannot see.
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
    if (!result.scenarios.some((s) => s.id === chosen.value)) {
      chosen.value = '';
    }
  } catch (failure) {
    chosen.value = '';
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
