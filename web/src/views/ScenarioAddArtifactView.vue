<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { CatalogArtifact, CatalogArtifactSummary, Honeytoken, Scenario } from '../api/generated';
import { errorText } from '../api/messages';
import PersonaFields from '../components/PersonaFields.vue';
import { isolate } from '../format';
import { locale, t, type Locale } from '../i18n';
import { personaProblems, personaToSend } from '../personaRules';
import { personaProblemTexts } from '../personaText';

/** The most pages of honeytokens that the page reads, so that it cannot loop without end. */
const maxPages = 10;

const route = useRoute();
const router = useRouter();

const id = computed(() => String(route.params.id));
const scenario = ref<Scenario | undefined>();
const choices = ref<CatalogArtifactSummary[]>([]);
const honeytokens = ref<Honeytoken[]>([]);
const truncated = ref(false);
const loading = ref(true);
const missing = ref(false);
const loadError = ref<string | undefined>();
const error = ref<string | undefined>();
const busy = ref(false);

const chosen = ref('');
const artifact = ref<CatalogArtifact | undefined>();
const detailError = ref<string | undefined>();
const language = ref<Locale>(locale.value);
const persona = ref<Record<string, string>>({});
const problems = ref<Record<string, string>>({});
// The honeytoken for each slot by its key; an empty string leaves the slot empty.
const bound = ref<Record<string, string>>({});
const slotProblems = ref<Record<string, string>>({});

const carries = computed(() => Object.values(bound.value).some((value) => value !== ''));

function fitting(accepts: readonly Honeytoken['type'][]): Honeytoken[] {
  return honeytokens.value.filter((h) => accepts.includes(h.type));
}

function chosenToken(key: string): Honeytoken | undefined {
  return honeytokens.value.find((h) => h.id === bound.value[key]);
}

/** Where the honeytoken leads, which is what the person is binding the file to. */
function target(h: Honeytoken): string {
  return h.trigger_url ?? h.trigger_names.join(', ');
}

// A required slot that no honeytoken of the scenario fits cannot be filled, whatever the person chooses.
const blocked = computed(() => artifact.value?.slots.some((slot) => !slot.optional && fitting(slot.accepts).length === 0) ?? false);

function show(failure: unknown): string {
  return errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
}

async function loadHoneytokens(): Promise<void> {
  const all: Honeytoken[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < maxPages; page++) {
    const { body } = await api.call('listHoneytokens', { query: { limit: 200, cursor, scenario_id: id.value } });
    all.push(...body.honeytokens);
    cursor = body.next_cursor;
    if (cursor === undefined) {
      break;
    }
  }
  honeytokens.value = all;
  truncated.value = cursor !== undefined;
}

async function load(): Promise<void> {
  loadError.value = undefined;
  try {
    const [found, list] = await Promise.all([
      api.call('getScenario', { path: { id: id.value } }),
      api.call('listCatalogArtifacts', { query: { lang: locale.value } }),
      loadHoneytokens(),
    ]);
    scenario.value = found.body;
    choices.value = list.body.artifacts;
  } catch (failure) {
    if (failure instanceof ApiError && failure.kind === 'not_found') {
      missing.value = true;
    } else {
      loadError.value = show(failure);
    }
  } finally {
    loading.value = false;
  }
}

// The answer to the last choice is the one that counts, whatever the order of the answers.
let asked = 0;

async function loadDetail(): Promise<void> {
  const mine = ++asked;
  detailError.value = undefined;
  error.value = undefined;
  problems.value = {};
  slotProblems.value = {};
  if (chosen.value === '') {
    artifact.value = undefined;
    return;
  }
  try {
    const body = (await api.call('getCatalogArtifact', { path: { id: chosen.value }, query: { lang: locale.value } })).body;
    if (mine !== asked) {
      return;
    }
    // A slot starts empty: binding a file to a honeytoken makes it a lure, and that is for the person to choose.
    // A new language keeps what was chosen for the same file.
    if (artifact.value?.id !== body.id) {
      bound.value = Object.fromEntries(body.slots.map((slot) => [slot.key, '']));
    }
    artifact.value = body;
  } catch (failure) {
    if (mine === asked) {
      artifact.value = undefined;
      detailError.value = show(failure);
    }
  }
}

function check(): boolean {
  const fields = artifact.value?.persona ?? [];
  const found = personaProblemTexts(fields, personaProblems(fields, persona.value, scenario.value?.persona));
  problems.value = found;
  const missingSlots: Record<string, string> = {};
  for (const slot of artifact.value?.slots ?? []) {
    if (!slot.optional && (bound.value[slot.key] ?? '') === '') {
      missingSlots[slot.key] = t('scenarios.addArtifact.slotRequired', { slot: slot.key });
    }
  }
  slotProblems.value = missingSlots;
  return Object.keys(found).length === 0 && Object.keys(missingSlots).length === 0;
}

async function submit(): Promise<void> {
  error.value = undefined;
  if (!check() || artifact.value === undefined || scenario.value === undefined) {
    return;
  }
  busy.value = true;
  try {
    // An empty slot is left out, which is what makes an optional one pocket litter.
    const bindings = Object.fromEntries(Object.entries(bound.value).filter(([, value]) => value !== ''));
    const { body } = await api.call('addScenarioArtifact', {
      path: { id: id.value },
      body: {
        catalog_artifact: artifact.value.id,
        language: language.value,
        persona: personaToSend(artifact.value.persona, persona.value, scenario.value.persona),
        bindings,
      },
    });
    await router.replace({ name: 'artifact', params: { id: body.artifact.id } });
  } catch (failure) {
    error.value = show(failure);
  } finally {
    busy.value = false;
  }
}

// Only the texts of the catalog depend on the language; the scenario and its honeytokens are not read
// again. The answer to the last question is the one that counts.
let askedChoices = 0;

async function reloadChoices(): Promise<void> {
  const mine = ++askedChoices;
  try {
    const body = (await api.call('listCatalogArtifacts', { query: { lang: locale.value } })).body.artifacts;
    if (mine === askedChoices) {
      choices.value = body;
    }
  } catch (failure) {
    if (mine === askedChoices) {
      loadError.value = show(failure);
    }
  }
}

onMounted(load);
watch(chosen, loadDetail);
watch(locale, () => {
  void reloadChoices();
  void loadDetail();
});
</script>

<template>
  <section>
    <p><RouterLink :to="{ name: 'scenario', params: { id } }">{{ t('scenarios.addArtifact.back') }}</RouterLink></p>

    <p v-if="loading" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="missing" class="notice" role="status">{{ t('error.not_found') }}</p>

    <template v-else-if="scenario">
      <div class="page-head">
        <div>
          <h1>{{ t('scenarios.addArtifact.title') }}</h1>
          <p class="lede"><bdi>{{ scenario.name }}</bdi></p>
        </div>
      </div>

      <p v-if="loadError" class="notice notice-error" role="alert">{{ loadError }}</p>

      <div class="section panel narrow">
        <p class="hint">{{ t('scenarios.addArtifact.hint') }}</p>
        <p v-if="choices.length === 0" class="notice" role="status">{{ t('scenarios.addArtifact.none') }}</p>
        <form v-else class="stack" novalidate @submit.prevent="submit">
          <div class="field">
            <label for="catalog-artifact">{{ t('scenarios.addArtifact.choose') }}</label>
            <select id="catalog-artifact" v-model="chosen">
              <option value="">{{ t('scenarios.addArtifact.choose') }}</option>
              <option v-for="choice in choices" :key="choice.id" :value="choice.id">{{ choice.title }}</option>
            </select>
          </div>

          <p v-if="detailError" class="notice notice-error" role="alert">{{ detailError }}</p>

          <template v-if="artifact">
            <p>{{ artifact.summary }}</p>
            <p class="hint">
              <bdi class="mono">{{ artifact.file_name }}</bdi>, {{ t(`artifactFormat.${artifact.format}`) }}
            </p>
            <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>

            <fieldset v-if="artifact.slots.length > 0" class="slots">
              <legend>{{ t('scenarios.addArtifact.slots') }}</legend>
              <p class="hint">{{ t('scenarios.addArtifact.slotsHint') }}</p>
              <p v-if="truncated" class="hint">{{ t('scenarios.addArtifact.truncated', { count: honeytokens.length }) }}</p>
              <div v-for="slot in artifact.slots" :key="slot.key" class="field">
                <label :for="`slot-${slot.key}`">
                  <span class="mono">{{ slot.key }}</span>
                  <span class="hint"> {{ slot.optional ? t('catalog.artifact.optional') : t('catalog.artifact.required') }}, {{ slot.accepts.map((type) => t(`honeytokenType.${type}`)).join(', ') }}</span>
                </label>
                <select :id="`slot-${slot.key}`" v-model="bound[slot.key]" :aria-invalid="slotProblems[slot.key] !== undefined" :aria-describedby="`slot-${slot.key}-hint`">
                  <option value="">{{ slot.optional ? t('scenarios.addArtifact.leaveEmpty') : t('scenarios.addArtifact.chooseHoneytoken') }}</option>
                  <option v-for="h in fitting(slot.accepts)" :key="h.id" :value="h.id">{{ isolate(h.name) }}, {{ t(`honeytokenType.${h.type}`) }}</option>
                </select>
                <span :id="`slot-${slot.key}-hint`" class="hint">
                  <template v-if="fitting(slot.accepts).length === 0">{{ t('scenarios.addArtifact.noneFitting') }}</template>
                  <template v-else-if="chosenToken(slot.key)">{{ t('scenarios.addArtifact.leadsTo') }} <bdi class="mono">{{ target(chosenToken(slot.key) as Honeytoken) }}</bdi></template>
                </span>
                <span v-if="slotProblems[slot.key]" class="hint problem" role="alert">{{ slotProblems[slot.key] }}</span>
              </div>
            </fieldset>

            <p class="verdict" role="status">
              <strong>{{ carries ? t('artifacts.role.lure') : t('artifacts.role.litter') }}.</strong>
              {{ carries ? t('scenarios.addArtifact.lureVerdict') : t('scenarios.addArtifact.litterVerdict') }}
            </p>

            <div class="field">
              <label for="placing-language">{{ t('scenarios.addArtifact.language') }}</label>
              <select id="placing-language" v-model="language">
                <option value="en">English</option>
                <option value="de">Deutsch</option>
              </select>
            </div>

            <PersonaFields
              v-model="persona"
              :fields="artifact.persona"
              :fixed="scenario.persona"
              :problems="problems"
              :legend="t('scenarios.addArtifact.persona')"
              :hint="t('scenarios.addArtifact.personaHint')"
            />

            <div class="actions-row">
              <button class="button button-primary" type="submit" :disabled="busy || blocked">{{ busy ? t('app.saving') : t('scenarios.addArtifact.submit') }}</button>
            </div>
          </template>
        </form>
      </div>
    </template>

    <p v-else-if="loadError" class="notice notice-error" role="alert">{{ loadError }}</p>
  </section>
</template>

<style scoped>
.hint {
  color: var(--slate);
  font-size: 0.8125rem;
}

.problem {
  color: var(--danger);
}

.narrow {
  max-width: 36rem;
}

.slots {
  display: grid;
  gap: 0.9rem;
  margin: 0;
  padding: 0.9rem;
  border: 1px solid var(--line);
  border-radius: var(--radius-sm);
}

.slots legend {
  padding: 0 0.3rem;
  font-weight: 600;
}

.verdict {
  margin: 0;
  padding: 0.6rem 0.8rem;
  border: 1px solid var(--line);
  border-radius: var(--radius-sm);
  background: var(--surface);
}
</style>
