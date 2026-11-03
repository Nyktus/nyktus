<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, ref } from 'vue';
import type { Honeytoken, OperationTypes } from '../api/generated';
import { t } from '../i18n';
import ScenarioSelect from './ScenarioSelect.vue';
import { parseTechniques } from '../techniques';

type Create = OperationTypes['createHoneytoken']['body'];
type Update = OperationTypes['updateHoneytoken']['body'];

const props = defineProps<{
  /** The honeytoken to change; without one, the form creates a new honeytoken. */
  existing?: Honeytoken;
  /** The scenario that a new honeytoken joins unless the person chooses another; only at creation. */
  scenario?: string;
  busy: boolean;
  submitLabel: string;
}>();

const emit = defineEmits<{ create: [body: Create]; update: [body: Update] }>();

const types = ['web_url', 'web_image', 'dns'] as const;
const severities = ['low', 'medium', 'high', 'critical'] as const;

const type = ref<Honeytoken['type']>(props.existing?.type ?? 'web_url');
const name = ref(props.existing?.name ?? '');
const notes = ref(props.existing?.notes ?? '');
const enabled = ref(props.existing?.enabled ?? true);
const redirect = ref(props.existing?.redirect_url ?? '');
const techniques = ref(props.existing?.techniques.join(', ') ?? '');
// An empty choice at creation means the default of the type.
const severity = ref<Honeytoken['severity'] | ''>(props.existing?.severity ?? '');
const scenarioId = ref(props.existing === undefined ? (props.scenario ?? '') : '');

const parsed = computed(() => parseTechniques(techniques.value));
const problem = computed(() =>
  parsed.value.invalid.length > 0 ? t('honeytokens.techniquesInvalid', { values: parsed.value.invalid.join(', ') }) : undefined,
);
const showRedirect = computed(() => type.value === 'web_url');

const nameMissing = ref(false);

function send(): void {
  const trimmed = name.value.trim();
  // A name of spaces passes the required field, and the server would refuse it without saying which field.
  nameMissing.value = trimmed === '';
  if (nameMissing.value || problem.value !== undefined) {
    return;
  }
  const target = redirect.value.trim();
  const existing = props.existing;
  if (existing === undefined) {
    const body: Create = { type: type.value, name: trimmed, notes: notes.value, enabled: enabled.value, techniques: parsed.value.ids };
    if (showRedirect.value && target !== '') {
      body.redirect_url = target;
    }
    if (severity.value !== '') {
      body.severity = severity.value;
    }
    if (scenarioId.value !== '') {
      body.scenario_id = scenarioId.value;
    }
    emit('create', body);
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
  if (enabled.value !== existing.enabled) {
    body.enabled = enabled.value;
  }
  if (existing.type === 'web_url' && target !== (existing.redirect_url ?? '')) {
    body.redirect_url = target === '' ? null : target;
  }
  if (parsed.value.ids.join(',') !== existing.techniques.join(',')) {
    body.techniques = parsed.value.ids;
  }
  if (severity.value !== '' && severity.value !== existing.severity) {
    body.severity = severity.value;
  }
  emit('update', body);
}
</script>

<template>
  <form class="stack" @submit.prevent="send">
    <div class="field">
      <label for="type">{{ t('field.type') }}</label>
      <select id="type" v-model="type" :disabled="existing !== undefined" aria-describedby="type-hint">
        <option v-for="option in types" :key="option" :value="option">{{ t(`honeytokenType.${option}`) }}</option>
      </select>
      <span id="type-hint" class="hint">{{ existing ? t('honeytokens.typeFixed') : t(`honeytokenType.${type}.hint`) }}</span>
    </div>

    <div class="field">
      <label for="name">{{ t('field.name') }}</label>
      <input id="name" v-model="name" type="text" required maxlength="100" :aria-describedby="nameMissing ? 'name-problem' : undefined" />
      <span v-if="nameMissing" id="name-problem" class="hint" role="alert">{{ t('field.nameRequired') }}</span>
    </div>

    <div class="field">
      <label for="notes">{{ t('field.notes') }}</label>
      <textarea id="notes" v-model="notes" maxlength="2000" aria-describedby="notes-hint"></textarea>
      <span id="notes-hint" class="hint">{{ t('honeytokens.notesHint') }}</span>
    </div>

    <div v-if="showRedirect" class="field">
      <label for="redirect">{{ t('honeytokens.redirect') }}</label>
      <input
        id="redirect"
        v-model="redirect"
        type="url"
        maxlength="2048"
        autocomplete="off"
        spellcheck="false"
        aria-describedby="redirect-hint"
      />
      <span id="redirect-hint" class="hint">{{ t('honeytokens.redirectHint') }}</span>
    </div>

    <div class="field">
      <label for="severity">{{ t('field.severity') }}</label>
      <select id="severity" v-model="severity">
        <option v-if="existing === undefined" value="">{{ t('severity.default') }}</option>
        <option v-for="option in severities" :key="option" :value="option">{{ t(`severity.${option}`) }}</option>
      </select>
    </div>

    <div class="field">
      <label for="techniques">{{ t('field.techniques') }}</label>
      <input
        id="techniques"
        v-model="techniques"
        type="text"
        class="mono"
        autocomplete="off"
        spellcheck="false"
        aria-describedby="techniques-hint"
        :aria-invalid="problem !== undefined"
      />
      <span id="techniques-hint" class="hint">{{ t('honeytokens.techniquesHint') }}</span>
      <span v-if="problem" class="hint problem" role="alert">{{ problem }}</span>
    </div>

    <ScenarioSelect v-if="existing === undefined" v-model="scenarioId" />

    <div class="field">
      <label class="check" for="enabled"><input id="enabled" v-model="enabled" type="checkbox" />{{ t('field.enabled') }}</label>
    </div>

    <div class="actions-row">
      <button class="button button-primary" type="submit" :disabled="busy">{{ busy ? t('app.saving') : submitLabel }}</button>
    </div>
  </form>
</template>

<style scoped>
.problem {
  color: var(--danger);
}
</style>
