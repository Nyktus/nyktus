<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { ref } from 'vue';
import type { OperationTypes, Scenario } from '../api/generated';
import { t } from '../i18n';
import EngageSelect from './EngageSelect.vue';

type Create = OperationTypes['createScenario']['body'];
type Update = OperationTypes['updateScenario']['body'];

const props = defineProps<{
  /** The scenario to change; without one, the form creates a new scenario. */
  existing?: Scenario;
  busy: boolean;
  submitLabel: string;
}>();

const emit = defineEmits<{ create: [body: Create]; update: [body: Update] }>();

const name = ref(props.existing?.name ?? '');
const notes = ref(props.existing?.notes ?? '');
const engage = ref<string[]>([...(props.existing?.engage_activities ?? [])]);

const nameMissing = ref(false);

function send(): void {
  const trimmed = name.value.trim();
  // A name of spaces passes the required field, and the server would refuse it without saying which field.
  nameMissing.value = trimmed === '';
  if (nameMissing.value) {
    return;
  }
  const existing = props.existing;
  if (existing === undefined) {
    emit('create', { name: trimmed, notes: notes.value, engage_activities: engage.value });
    return;
  }
  // Members that are left out stay as they are, so only what the user changed is sent.
  const body: Update = {};
  if (trimmed !== existing.name) {
    body.name = trimmed;
  }
  if (notes.value !== existing.notes) {
    body.notes = notes.value;
  }
  if (engage.value.join(',') !== existing.engage_activities.join(',')) {
    body.engage_activities = engage.value;
  }
  emit('update', body);
}
</script>

<template>
  <form class="stack" @submit.prevent="send">
    <div class="field">
      <label for="name">{{ t('field.name') }}</label>
      <input id="name" v-model="name" type="text" required maxlength="100" :aria-describedby="nameMissing ? 'name-problem' : undefined" />
      <span v-if="nameMissing" id="name-problem" class="hint" role="alert">{{ t('field.nameRequired') }}</span>
    </div>
    <div class="field">
      <label for="notes">{{ t('field.notes') }}</label>
      <textarea id="notes" v-model="notes" maxlength="2000" aria-describedby="notes-hint"></textarea>
      <span id="notes-hint" class="hint">{{ t('scenarios.notesHint') }}</span>
    </div>
    <EngageSelect v-model="engage" />
    <div class="actions-row">
      <button class="button button-primary" type="submit" :disabled="busy">{{ busy ? t('app.saving') : submitLabel }}</button>
    </div>
  </form>
</template>
