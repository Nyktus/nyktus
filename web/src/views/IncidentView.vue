<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useRoute } from 'vue-router';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { Incident, TriageIncidentRequest } from '../api/generated';
import { errorText } from '../api/messages';
import ConfirmDialog from '../components/ConfirmDialog.vue';
import IncidentEvents from '../components/IncidentEvents.vue';
import IncidentStatusBadge from '../components/IncidentStatusBadge.vue';
import ResourceRef from '../components/ResourceRef.vue';
import SeverityBadge from '../components/SeverityBadge.vue';
import TimeStamp from '../components/TimeStamp.vue';
import { t } from '../i18n';
import { useResourceNames } from '../resourceNames';
import { session } from '../session';
import { parseTechniques } from '../techniques';

const route = useRoute();

const severities = ['info', 'low', 'medium', 'high', 'critical'] as const;

const id = computed(() => String(route.params.id));
const incident = ref<Incident | undefined>();
const loading = ref(true);
const missing = ref(false);
const error = ref<string | undefined>();
const saved = ref(false);
const busy = ref(false);
const closing = ref(false);
const canWrite = computed(() => session.can('incidents:write'));

const names = useResourceNames();

// The state of the form. It is set from the incident when the page loads and when
// the form is saved, not when the status changes, so that a status change does not
// discard what the user has typed.
const notes = ref('');
const severity = ref<Incident['severity'] | ''>('');
const overrideTechniques = ref(false);
const techniques = ref('');

const parsed = computed(() => parseTechniques(techniques.value));
const problem = computed(() =>
  overrideTechniques.value && parsed.value.invalid.length > 0 ? t('honeytokens.techniquesInvalid', { values: parsed.value.invalid.join(', ') }) : undefined,
);

function show(failure: unknown): string {
  return errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
}

function adoptForm(from: Incident): void {
  notes.value = from.notes;
  severity.value = from.severity_override ?? '';
  overrideTechniques.value = from.techniques_override !== null;
  techniques.value = (from.techniques_override ?? from.event_techniques).join(', ');
}

async function load(): Promise<void> {
  loading.value = true;
  error.value = undefined;
  try {
    const loaded = (await api.call('getIncident', { path: { id: id.value } })).body;
    incident.value = loaded;
    adoptForm(loaded);
    void names.resolve([loaded]);
  } catch (failure) {
    if (failure instanceof ApiError && failure.kind === 'not_found') {
      missing.value = true;
    } else {
      error.value = show(failure);
    }
  } finally {
    loading.value = false;
  }
}

/** Sends a triage and returns the incident after it, or nothing when the server refused. */
async function triage(body: TriageIncidentRequest): Promise<Incident | undefined> {
  error.value = undefined;
  saved.value = false;
  busy.value = true;
  try {
    return (await api.call('triageIncident', { path: { id: id.value }, body })).body;
  } catch (failure) {
    error.value = show(failure);
    if (failure instanceof ApiError && failure.kind === 'invalid_state') {
      // Someone else moved the status; show where it is now.
      try {
        incident.value = (await api.call('getIncident', { path: { id: id.value } })).body;
      } catch {
        // The error above is what the user needs to read.
      }
    }
    return undefined;
  } finally {
    busy.value = false;
    closing.value = false;
  }
}

async function move(status: 'acknowledged' | 'closed'): Promise<void> {
  const after = await triage({ status });
  if (after !== undefined) {
    incident.value = after;
  }
}

async function save(): Promise<void> {
  const current = incident.value;
  if (current === undefined || problem.value !== undefined) {
    return;
  }
  // Members that are left out stay as they are, so only what the user changed is sent.
  const body: TriageIncidentRequest = {};
  if (notes.value !== current.notes) {
    body.notes = notes.value;
  }
  const chosen = severity.value === '' ? null : severity.value;
  if (chosen !== current.severity_override) {
    body.severity_override = chosen;
  }
  if (!overrideTechniques.value) {
    if (current.techniques_override !== null) {
      body.techniques_override = null;
    }
  } else if (current.techniques_override === null || parsed.value.ids.join(',') !== current.techniques_override.join(',')) {
    body.techniques_override = parsed.value.ids;
  }
  if (Object.keys(body).length === 0) {
    saved.value = true;
    return;
  }
  const after = await triage(body);
  if (after !== undefined) {
    incident.value = after;
    adoptForm(after);
    saved.value = true;
  }
}

onMounted(load);
</script>

<template>
  <section>
    <p><RouterLink :to="{ name: 'incidents' }">{{ t('incident.back') }}</RouterLink></p>

    <p v-if="loading" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="missing" class="notice" role="status">{{ t('error.not_found') }}</p>

    <template v-else-if="incident">
      <div class="page-head">
        <div>
          <h1>{{ t('incident.title') }}</h1>
          <p class="badges">
            <IncidentStatusBadge :status="incident.status" />
            <SeverityBadge :severity="incident.severity" />
          </p>
        </div>
        <div v-if="canWrite && incident.status !== 'closed'" class="actions-row">
          <button v-if="incident.status === 'open'" class="button button-primary" type="button" :disabled="busy" @click="move('acknowledged')">
            {{ t('incident.acknowledge') }}
          </button>
          <button class="button button-ghost" type="button" :disabled="busy" @click="closing = true">{{ t('incident.close') }}</button>
        </div>
      </div>

      <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>
      <p v-if="incident.status === 'closed'" class="notice" role="status">{{ t('incident.closedNote') }}</p>

      <div class="section panel">
        <dl class="definition">
          <dt>{{ t('field.resource') }}</dt>
          <dd><ResourceRef :type="incident.resource_type" :id="incident.resource_id" :entry="names.entries.value[names.key(incident.resource_type, incident.resource_id)]" /></dd>
          <dt>{{ t('field.severity') }}</dt>
          <dd>
            <SeverityBadge :severity="incident.severity" />
            <span v-if="incident.severity_override !== null" class="hint">{{ t('incident.overridden', { severity: t(`severity.${incident.event_severity}`) }) }}</span>
          </dd>
          <dt>{{ t('field.techniques') }}</dt>
          <dd class="mono">{{ incident.techniques.length === 0 ? t('common.none') : incident.techniques.join(', ') }}</dd>
          <template v-if="incident.techniques_override !== null">
            <dt>{{ t('incident.eventTechniques') }}</dt>
            <dd class="mono">{{ incident.event_techniques.length === 0 ? t('common.none') : incident.event_techniques.join(', ') }}</dd>
          </template>
          <dt>{{ t('field.events') }}</dt>
          <dd>{{ incident.event_count }}</dd>
          <dt>{{ t('field.firstEvent') }}</dt>
          <dd><TimeStamp :value="incident.first_event_at" /></dd>
          <dt>{{ t('field.lastEvent') }}</dt>
          <dd><TimeStamp :value="incident.last_event_at" /></dd>
          <dt>{{ t('field.opened') }}</dt>
          <dd><TimeStamp :value="incident.opened_at" /></dd>
          <template v-if="incident.acknowledged_at !== null">
            <dt>{{ t('field.acknowledged') }}</dt>
            <dd><TimeStamp :value="incident.acknowledged_at" /></dd>
          </template>
          <template v-if="incident.closed_at !== null">
            <dt>{{ t('field.closed') }}</dt>
            <dd><TimeStamp :value="incident.closed_at" /></dd>
          </template>
          <template v-if="!canWrite">
            <dt>{{ t('field.notes') }}</dt>
            <dd class="notes">{{ incident.notes === '' ? t('common.none') : incident.notes }}</dd>
          </template>
        </dl>
      </div>

      <div v-if="canWrite" class="section panel narrow">
        <h2>{{ t('incident.triage') }}</h2>
        <p v-if="saved" class="notice notice-ok" role="status">{{ t('common.saved') }}</p>
        <form class="stack" @submit.prevent="save">
          <div class="field">
            <label for="notes">{{ t('field.notes') }}</label>
            <textarea id="notes" v-model="notes" maxlength="10000" aria-describedby="notes-hint"></textarea>
            <span id="notes-hint" class="hint">{{ t('incident.notesHint') }}</span>
          </div>

          <div class="field">
            <label for="severity">{{ t('incident.severityOverride') }}</label>
            <select id="severity" v-model="severity" aria-describedby="severity-hint">
              <option value="">{{ t('incident.severityNone') }}</option>
              <option v-for="option in severities" :key="option" :value="option">{{ t(`severity.${option}`) }}</option>
            </select>
            <span id="severity-hint" class="hint">{{ t('incident.severityHint', { severity: t(`severity.${incident.event_severity}`) }) }}</span>
          </div>

          <div class="field">
            <label class="check" for="override-techniques"><input id="override-techniques" v-model="overrideTechniques" type="checkbox" />{{ t('incident.techniquesOverride') }}</label>
          </div>
          <div v-if="overrideTechniques" class="field">
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
            <span id="techniques-hint" class="hint">{{ t('incident.techniquesHint') }}</span>
            <span v-if="problem" class="hint problem" role="alert">{{ problem }}</span>
          </div>

          <div class="actions-row">
            <button class="button button-primary" type="submit" :disabled="busy">{{ busy ? t('app.saving') : t('common.save') }}</button>
          </div>
        </form>
      </div>

      <div class="section panel">
        <h2>{{ t('incident.events') }}</h2>
        <p class="hint">{{ t('event.personalData') }}</p>
        <IncidentEvents :incident-id="incident.id" :event-count="incident.event_count" />
      </div>

      <ConfirmDialog
        v-if="canWrite"
        :open="closing"
        :title="t('incident.closeTitle')"
        :confirm="t('incident.closeConfirm')"
        :busy="busy"
        @confirm="move('closed')"
        @cancel="closing = false"
      >
        {{ t('incident.closeBody') }}
      </ConfirmDialog>
    </template>

    <p v-else-if="error" class="notice notice-error" role="alert">{{ error }}</p>
  </section>
</template>

<style scoped>
.badges {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
  margin-top: 0.5rem;
}

.notes {
  white-space: pre-wrap;
}

.narrow {
  max-width: 36rem;
}

.problem {
  color: var(--danger);
}
</style>
