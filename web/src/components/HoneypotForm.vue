<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, ref } from 'vue';
import type { Honeypot, OperationTypes } from '../api/generated';
import { t } from '../i18n';
import ScenarioSelect from './ScenarioSelect.vue';
import { honeypotServices, severities } from '../resourceChoices';
import type { Prefill } from '../slotPrefill';
import { parseTechniques } from '../techniques';

type Create = OperationTypes['createHoneypot']['body'];
type Update = OperationTypes['updateHoneypot']['body'];

const props = defineProps<{
  /** The honeypot to change; without one, the form creates a new honeypot. */
  existing?: Honeypot;
  /** The scenario that a new honeypot joins unless the person chooses another; only at creation. */
  scenario?: string;
  /** What a link fills in beforehand, such as the service and the name of a slot; only at creation. */
  prefill?: Prefill;
  busy: boolean;
  submitLabel: string;
}>();

const emit = defineEmits<{ create: [body: Create]; update: [body: Update] }>();

const services = honeypotServices;

const service = ref<Honeypot['service']>(props.existing?.service ?? props.prefill?.service ?? 'ssh');
const name = ref(props.existing?.name ?? props.prefill?.name ?? '');
const notes = ref(props.existing?.notes ?? '');
const enabled = ref(props.existing?.enabled ?? true);
const techniques = ref(props.existing?.techniques.join(', ') ?? props.prefill?.techniques?.join(', ') ?? '');
// An empty choice at creation means the default of the server.
const severity = ref<Honeypot['severity'] | ''>(props.existing?.severity ?? props.prefill?.severity ?? '');
const scenarioId = ref('');

const parsed = computed(() => parseTechniques(techniques.value));
const problem = computed(() =>
  parsed.value.invalid.length > 0 ? t('honeytokens.techniquesInvalid', { values: parsed.value.invalid.join(', ') }) : undefined,
);

const nameMissing = ref(false);

function send(): void {
  const trimmed = name.value.trim();
  // A name of spaces passes the required field, and the server would refuse it without saying which field.
  nameMissing.value = trimmed === '';
  if (nameMissing.value || problem.value !== undefined) {
    return;
  }
  const existing = props.existing;
  if (existing === undefined) {
    const body: Create = { service: service.value, name: trimmed, notes: notes.value, enabled: enabled.value, techniques: parsed.value.ids };
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
      <label for="service">{{ t('field.type') }}</label>
      <select id="service" v-model="service" :disabled="existing !== undefined" aria-describedby="service-hint">
        <option v-for="option in services" :key="option" :value="option">{{ t(`honeypotService.${option}`) }}</option>
      </select>
      <span id="service-hint" class="hint">{{ existing ? t('honeypots.serviceFixed') : t(`honeypotService.${service}.hint`) }}</span>
    </div>

    <div class="field">
      <label for="name">{{ t('field.name') }}</label>
      <input id="name" v-model="name" type="text" required maxlength="100" :aria-describedby="nameMissing ? 'name-problem' : undefined" />
      <span v-if="nameMissing" id="name-problem" class="hint" role="alert">{{ t('field.nameRequired') }}</span>
    </div>

    <div class="field">
      <label for="notes">{{ t('field.notes') }}</label>
      <textarea id="notes" v-model="notes" maxlength="2000" aria-describedby="notes-hint"></textarea>
      <span id="notes-hint" class="hint">{{ t('honeypots.notesHint') }}</span>
    </div>

    <div class="field">
      <label for="severity">{{ t('field.severity') }}</label>
      <select id="severity" v-model="severity">
        <option v-if="existing === undefined" value="">{{ t('severity.medium') }}</option>
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

    <ScenarioSelect v-if="existing === undefined" v-model="scenarioId" :preselected="scenario" />

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
