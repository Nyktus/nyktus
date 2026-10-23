<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { CatalogDeception } from '../api/generated';
import { errorText } from '../api/messages';
import SeverityBadge from '../components/SeverityBadge.vue';
import { locale, t, type Locale } from '../i18n';
import { checkPersonaValue } from '../personaRules';
import { session } from '../session';

const route = useRoute();
const router = useRouter();

const id = computed(() => String(route.params.id));
const deception = ref<CatalogDeception | undefined>();
const loading = ref(true);
const missing = ref(false);
const error = ref<string | undefined>();
const loadError = ref<string | undefined>();
const nameMissing = ref(false);
const busy = ref(false);
const canApply = computed(() => session.can('scenarios:write'));

const name = ref('');
const notes = ref('');
const language = ref<Locale>(locale.value);
const persona = reactive<Record<string, string>>({});
const problems = ref<Record<string, string>>({});

function show(failure: unknown): string {
  return errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
}

// A change of the language asks again; the answer of the last question is the one that counts.
let asked = 0;

async function load(): Promise<void> {
  const mine = ++asked;
  loadError.value = undefined;
  try {
    const previous = deception.value;
    const body = (await api.call('getCatalogDeception', { path: { id: id.value }, query: { lang: locale.value } })).body;
    if (mine !== asked) {
      return;
    }
    deception.value = body;
    if (previous === undefined || name.value === previous.title) {
      name.value = body.title;
    }
    for (const field of body.persona) {
      persona[field.key] ??= '';
    }
  } catch (failure) {
    if (mine !== asked) {
      return;
    }
    if (failure instanceof ApiError && failure.kind === 'not_found') {
      missing.value = true;
    } else {
      loadError.value = show(failure);
    }
  } finally {
    if (mine === asked) {
      loading.value = false;
    }
  }
}

function check(): Record<string, string> {
  const found: Record<string, string> = {};
  for (const field of deception.value?.persona ?? []) {
    const problem = checkPersonaValue(field.kind, persona[field.key] ?? '');
    if (problem === 'required') {
      found[field.key] = t('catalog.apply.required', { label: field.label });
    } else if (problem === 'host') {
      found[field.key] = t('catalog.apply.hostInvalid', { label: field.label });
    } else if (problem === 'text') {
      found[field.key] = t('catalog.apply.textInvalid', { label: field.label });
    }
  }
  return found;
}

async function apply(): Promise<void> {
  error.value = undefined;
  problems.value = check();
  // A name of spaces passes the required field, and the server would refuse it without saying which field.
  nameMissing.value = name.value.trim() === '';
  if (nameMissing.value || Object.keys(problems.value).length > 0 || deception.value === undefined) {
    return;
  }
  busy.value = true;
  try {
    const values: Record<string, string> = {};
    for (const field of deception.value.persona) {
      values[field.key] = (persona[field.key] ?? '').trim();
    }
    const { body } = await api.call('applyCatalogDeception', {
      path: { id: id.value },
      body: { name: name.value.trim(), notes: notes.value, language: language.value, persona: values },
    });
    await router.replace({ name: 'scenario', params: { id: body.scenario.id } });
  } catch (failure) {
    error.value = show(failure);
  } finally {
    busy.value = false;
  }
}

onMounted(load);
watch(locale, load);
</script>

<template>
  <section>
    <p><RouterLink :to="{ name: 'catalog' }">{{ t('catalog.back') }}</RouterLink></p>

    <p v-if="loading" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="missing" class="notice" role="status">{{ t('error.not_found') }}</p>

    <template v-else-if="deception">
      <p v-if="loadError" class="notice notice-error" role="alert">{{ loadError }}</p>
      <div class="page-head">
        <div>
          <h1>{{ deception.title }}</h1>
          <p class="lede">{{ deception.summary }}</p>
          <p class="badges"><span class="badge">{{ t(`category.${deception.category}`) }}</span></p>
        </div>
      </div>

      <div class="section panel">
        <dl class="definition">
          <dt>{{ t('catalog.techniques') }}</dt>
          <dd class="mono">{{ deception.techniques.join(', ') }}</dd>
          <dt>{{ t('catalog.engage') }}</dt>
          <dd class="mono">{{ deception.engage_activities.join(', ') }}</dd>
        </dl>
      </div>

      <div class="section panel">
        <h2>{{ t('catalog.creates') }}</h2>
        <p v-if="deception.honeytokens.length === 0 && deception.artifacts.length === 0" class="hint">{{ t('catalog.guideOnly') }}</p>
        <template v-if="deception.honeytokens.length > 0">
          <h3>{{ t('catalog.honeytokens') }}</h3>
          <div class="table-wrap">
            <table class="table">
              <tbody>
                <tr v-for="honeytoken in deception.honeytokens" :key="honeytoken.key">
                  <td>{{ honeytoken.label }}</td>
                  <td>{{ t(`honeytokenType.${honeytoken.type}`) }}</td>
                  <td><SeverityBadge :severity="honeytoken.severity" /></td>
                  <td class="mono">{{ honeytoken.techniques.join(', ') }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </template>
        <template v-if="deception.artifacts.length > 0">
          <h3>{{ t('catalog.artifacts') }}</h3>
          <div class="table-wrap">
            <table class="table">
              <tbody>
                <tr v-for="artifact in deception.artifacts" :key="artifact.key">
                  <td class="mono">{{ artifact.file_name }}</td>
                  <td>{{ t(`artifactFormat.${artifact.format}`) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </template>
        <p v-if="deception.secrets.length > 0">
          <strong>{{ t('catalog.secrets') }}:</strong> {{ t('catalog.secretsValue', { count: deception.secrets.length }) }}
        </p>
      </div>

      <div v-if="canApply" class="section panel narrow">
        <h2>{{ t('catalog.apply.title') }}</h2>
        <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>
        <form class="stack" novalidate @submit.prevent="apply">
          <div class="field">
            <label for="name">{{ t('field.name') }}</label>
            <input id="name" v-model="name" type="text" required maxlength="100" :aria-describedby="nameMissing ? 'name-problem' : undefined" />
            <span v-if="nameMissing" id="name-problem" class="hint problem" role="alert">{{ t('field.nameRequired') }}</span>
          </div>
          <div class="field">
            <label for="notes">{{ t('field.notes') }}</label>
            <textarea id="notes" v-model="notes" maxlength="2000"></textarea>
          </div>
          <div class="field">
            <label for="guide-language">{{ t('catalog.apply.language') }}</label>
            <select id="guide-language" v-model="language">
              <option value="en">English</option>
              <option value="de">Deutsch</option>
            </select>
          </div>

          <fieldset v-if="deception.persona.length > 0" class="persona">
            <legend>{{ t('catalog.apply.persona') }}</legend>
            <p class="hint">{{ t('catalog.apply.personaHint') }}</p>
            <div v-for="field in deception.persona" :key="field.key" class="field">
              <label :for="`persona-${field.key}`">{{ field.label }}</label>
              <input
                :id="`persona-${field.key}`"
                v-model="persona[field.key]"
                type="text"
                autocomplete="off"
                spellcheck="false"
                :placeholder="field.example"
                :aria-describedby="`persona-${field.key}-hint`"
                :aria-invalid="problems[field.key] !== undefined"
                :maxlength="field.kind === 'text' ? 200 : 253"
              />
              <span :id="`persona-${field.key}-hint`" class="hint">
                {{ t(`catalog.apply.${field.kind}`) }} {{ t('catalog.apply.example', { example: field.example }) }}
              </span>
              <span v-if="problems[field.key]" class="hint problem" role="alert">{{ problems[field.key] }}</span>
            </div>
          </fieldset>

          <div class="actions-row">
            <button class="button button-primary" type="submit" :disabled="busy">{{ busy ? t('app.saving') : t('catalog.apply.submit') }}</button>
          </div>
        </form>
      </div>
    </template>

    <p v-else-if="loadError" class="notice notice-error" role="alert">{{ loadError }}</p>
  </section>
</template>

<style scoped>
.badges {
  margin-top: 0.5rem;
}

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

.persona {
  display: grid;
  gap: 0.9rem;
  margin: 0;
  padding: 0.9rem;
  border: 1px solid var(--line);
  border-radius: var(--radius-sm);
}

.persona legend {
  padding: 0 0.3rem;
  font-weight: 600;
}

h3 {
  font-size: 0.95rem;
}
</style>
