<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { CatalogDeception, CatalogDeceptionSummary, Scenario } from '../api/generated';
import { errorText } from '../api/messages';
import FileChoice from '../components/FileChoice.vue';
import PersonaFields from '../components/PersonaFields.vue';
import { locale, t, type Locale } from '../i18n';
import { personaProblems, personaToSend } from '../personaRules';
import { personaProblemText } from '../personaText';

const route = useRoute();
const router = useRouter();

const id = computed(() => String(route.params.id));
const scenario = ref<Scenario | undefined>();
const choices = ref<CatalogDeceptionSummary[]>([]);
const loading = ref(true);
const missing = ref(false);
const loadError = ref<string | undefined>();
const error = ref<string | undefined>();
const busy = ref(false);

const chosen = ref('');
const deception = ref<CatalogDeception | undefined>();
const detailError = ref<string | undefined>();
const language = ref<Locale>(locale.value);
const persona = ref<Record<string, string>>({});
const problems = ref<Record<string, string>>({});
const selected = ref<string[]>([]);

const added = computed(() => new Set(scenario.value?.deceptions.map((d) => d.deception_id)));
const available = computed(() => choices.value.filter((c) => !added.value.has(c.id)));

function show(failure: unknown): string {
  return errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
}

async function load(): Promise<void> {
  loadError.value = undefined;
  try {
    const [found, list] = await Promise.all([
      api.call('getScenario', { path: { id: id.value } }),
      api.call('listCatalogDeceptions', { query: { lang: locale.value } }),
    ]);
    scenario.value = found.body;
    choices.value = list.body.deceptions;
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
  if (chosen.value === '') {
    deception.value = undefined;
    return;
  }
  try {
    const body = (await api.call('getCatalogDeception', { path: { id: chosen.value }, query: { lang: locale.value } })).body;
    if (mine !== asked) {
      return;
    }
    // What was typed stays, so that a key that two deceptions ask for is asked once.
    deception.value = body;
    selected.value = body.artifacts.map((a) => a.key);
  } catch (failure) {
    if (mine === asked) {
      deception.value = undefined;
      detailError.value = show(failure);
    }
  }
}

function check(): Record<string, string> {
  const fields = deception.value?.persona ?? [];
  const found: Record<string, string> = {};
  for (const [key, problem] of Object.entries(personaProblems(fields, persona.value, scenario.value?.persona))) {
    const field = fields.find((f) => f.key === key);
    if (field !== undefined) {
      found[key] = personaProblemText(field, problem);
    }
  }
  return found;
}

async function submit(): Promise<void> {
  error.value = undefined;
  problems.value = check();
  if (Object.keys(problems.value).length > 0 || deception.value === undefined || scenario.value === undefined) {
    return;
  }
  busy.value = true;
  try {
    await api.call('addScenarioDeception', {
      path: { id: id.value },
      body: {
        deception_id: deception.value.id,
        language: language.value,
        // A key that the scenario has is not sent: its value stays, and a different one would be refused.
        persona: personaToSend(deception.value.persona, persona.value, scenario.value.persona),
        artifacts: deception.value.artifacts.map((a) => a.key).filter((key) => selected.value.includes(key)),
      },
    });
    await router.replace({ name: 'scenario', params: { id: id.value } });
  } catch (failure) {
    error.value = show(failure);
  } finally {
    busy.value = false;
  }
}

onMounted(load);
watch(chosen, loadDetail);
watch(locale, () => {
  void load();
  void loadDetail();
});
</script>

<template>
  <section>
    <p><RouterLink :to="{ name: 'scenario', params: { id } }">{{ t('scenarios.addDeception.back') }}</RouterLink></p>

    <p v-if="loading" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="missing" class="notice" role="status">{{ t('error.not_found') }}</p>

    <template v-else-if="scenario">
      <div class="page-head">
        <div>
          <h1>{{ t('scenarios.addDeception.title') }}</h1>
          <p class="lede"><bdi>{{ scenario.name }}</bdi></p>
        </div>
      </div>

      <p v-if="loadError" class="notice notice-error" role="alert">{{ loadError }}</p>

      <div class="section panel narrow">
        <p class="hint">{{ t('scenarios.addDeception.hint') }}</p>
        <p v-if="available.length === 0" class="notice" role="status">{{ t('scenarios.addDeception.none') }}</p>
        <form v-else class="stack" novalidate @submit.prevent="submit">
          <div class="field">
            <label for="deception">{{ t('scenarios.addDeception.choose') }}</label>
            <select id="deception" v-model="chosen">
              <option value="">{{ t('scenarios.addDeception.choose') }}</option>
              <option v-for="choice in choices" :key="choice.id" :value="choice.id" :disabled="added.has(choice.id)">
                {{ added.has(choice.id) ? t('scenarios.addDeception.already', { title: choice.title }) : choice.title }}
              </option>
            </select>
          </div>

          <p v-if="detailError" class="notice notice-error" role="alert">{{ detailError }}</p>

          <template v-if="deception">
            <p>{{ deception.summary }}</p>
            <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>

            <div class="field">
              <label for="guide-language">{{ t('catalog.apply.language') }}</label>
              <select id="guide-language" v-model="language">
                <option value="en">English</option>
                <option value="de">Deutsch</option>
              </select>
            </div>

            <PersonaFields
              v-model="persona"
              :fields="deception.persona"
              :fixed="scenario.persona"
              :problems="problems"
              :legend="t('catalog.apply.persona')"
              :hint="t('scenarios.addDeception.personaHint')"
            />

            <FileChoice v-model="selected" :artifacts="deception.artifacts" :hint="t('scenarios.addDeception.filesHint')" />

            <div class="actions-row">
              <button class="button button-primary" type="submit" :disabled="busy">{{ busy ? t('app.saving') : t('scenarios.addDeception.submit') }}</button>
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

.narrow {
  max-width: 36rem;
}
</style>
