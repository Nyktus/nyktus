<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { CatalogDeception, OperationTypes, Scenario } from '../api/generated';
import { errorText } from '../api/messages';
import ConfirmDialog from '../components/ConfirmDialog.vue';
import ScenarioDeceptionBlock from '../components/ScenarioDeceptionBlock.vue';
import ScenarioForm from '../components/ScenarioForm.vue';
import ScenarioResources from '../components/ScenarioResources.vue';
import TimeStamp from '../components/TimeStamp.vue';
import { engageLabel, useEngageNames } from '../engageNames';
import { locale, t } from '../i18n';
import { session } from '../session';

const route = useRoute();
const router = useRouter();

const id = computed(() => String(route.params.id));
const scenario = ref<Scenario | undefined>();
const loading = ref(true);
const missing = ref(false);
const error = ref<string | undefined>();
const saved = ref(false);
const busy = ref(false);
const deleting = ref(false);
// A honeytoken that a slot created leads back here, so the page says that it was created. The note belongs to that
// arrival only: it goes from the address at once, and with the next change on the page.
const created = ref(route.query.created === '1');
const canWrite = computed(() => session.can('scenarios:write'));
// Deleting the resources with the scenario needs the permissions to write both of them.
const canDeleteResources = computed(() => session.can('honeytokens:write') && session.can('honeypots:write'));

// Whether the honeytokens and honeypots of the scenario are deleted with it. Keeping them is the safe choice.
const withResources = ref(false);

// Whatever closes the dialog, the next one starts with keeping: a choice to delete that was made and given up must not
// be the one that a later click on "Delete" carries out.
watch(deleting, () => {
  withResources.value = false;
});

// The deception that the dialog asks about, and whether the request is on its way.
const removeTarget = ref<string | undefined>();
const removing = ref(false);

// The titles come from the list of the catalog, in the language of the console. A deception that the list lacks is gone
// from the catalog. The slots, files and guide of the others are read at once, in the same language; one that could not be
// read is asked for again on request.
const titles = ref<Record<string, string> | undefined>();
const titlesFailed = ref(false);
const details = ref<Record<string, CatalogDeception | 'failed'>>({});
const engageNames = useEngageNames();

function show(failure: unknown): string {
  return errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
}

// The answer of the last question is the one that counts, also when the language changes meanwhile.
let asked = 0;

async function loadDetail(deceptionId: string, mine: number, language: typeof locale.value): Promise<void> {
  try {
    const body = (await api.call('getCatalogDeception', { path: { id: deceptionId }, query: { lang: language } })).body;
    if (mine === asked) {
      details.value = { ...details.value, [deceptionId]: body };
    }
  } catch {
    if (mine === asked) {
      details.value = { ...details.value, [deceptionId]: 'failed' };
    }
  }
}

async function loadCatalog(): Promise<void> {
  const mine = ++asked;
  const language = locale.value;
  titlesFailed.value = false;
  titles.value = undefined;
  details.value = {};
  const entries = scenario.value?.deceptions ?? [];
  // A scenario without deceptions has nothing to name.
  if (entries.length === 0) {
    return;
  }
  let list;
  try {
    list = (await api.call('listCatalogDeceptions', { query: { lang: language } })).body.deceptions;
  } catch {
    if (mine !== asked) {
      return;
    }
    // Without the list nothing is known to be gone, so every deception is asked for itself; its detail names it.
    titlesFailed.value = true;
    await Promise.all(entries.map((entry) => loadDetail(entry.deception_id, mine, language)));
    return;
  }
  if (mine !== asked) {
    return;
  }
  const known = Object.fromEntries(list.map((entry) => [entry.id, entry.title]));
  titles.value = known;
  await Promise.all(entries.filter((entry) => entry.deception_id in known).map((entry) => loadDetail(entry.deception_id, mine, language)));
}

function retry(deceptionId: string): void {
  const rest = { ...details.value };
  delete rest[deceptionId];
  details.value = rest;
  void loadDetail(deceptionId, asked, locale.value);
}

// The catalog lacks a deception that its list does not name, once the list has been read.
function gone(deceptionId: string): boolean {
  return titles.value !== undefined && !(deceptionId in titles.value);
}

async function load(): Promise<void> {
  loading.value = true;
  error.value = undefined;
  try {
    scenario.value = (await api.call('getScenario', { path: { id: id.value } })).body;
    void loadCatalog();
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

// Removing a deception ends the assignment only; its honeytokens and honeypots stay in the scenario.
async function removeDeception(): Promise<void> {
  created.value = false;
  const deceptionId = removeTarget.value;
  if (deceptionId === undefined) {
    return;
  }
  removing.value = true;
  error.value = undefined;
  try {
    scenario.value = (await api.call('removeScenarioDeception', { path: { id: id.value, deception_id: deceptionId } })).body;
  } catch (failure) {
    error.value = show(failure);
  } finally {
    removing.value = false;
    removeTarget.value = undefined;
  }
}

async function update(body: OperationTypes['updateScenario']['body']): Promise<void> {
  created.value = false;
  error.value = undefined;
  saved.value = false;
  if (Object.keys(body).length === 0) {
    saved.value = true;
    return;
  }
  busy.value = true;
  try {
    scenario.value = (await api.call('updateScenario', { path: { id: id.value }, body })).body;
    saved.value = true;
  } catch (failure) {
    error.value = show(failure);
  } finally {
    busy.value = false;
  }
}

async function remove(): Promise<void> {
  busy.value = true;
  try {
    // Keeping is what the server does without a parameter, so only deleting is asked for.
    const query: OperationTypes['deleteScenario']['query'] = {};
    if (withResources.value && canDeleteResources.value) {
      query.honeytokens = 'delete';
      query.honeypots = 'delete';
    }
    await api.call('deleteScenario', { path: { id: id.value }, query });
    await router.replace({ name: 'scenarios' });
  } catch (failure) {
    deleting.value = false;
    error.value = show(failure);
  } finally {
    busy.value = false;
  }
}

const engageText = computed(() => {
  const ids = scenario.value?.engage_activities ?? [];
  return ids.length === 0 ? t('common.none') : ids.map((activity) => engageLabel(activity, engageNames.value)).join(', ');
});

onMounted(() => {
  if (created.value) {
    void router.replace({ name: 'scenario', params: { id: id.value } });
  }
  void load();
});
watch(locale, () => {
  void loadCatalog();
});
</script>

<template>
  <section>
    <p><RouterLink :to="{ name: 'scenarios' }">{{ t('scenarios.back') }}</RouterLink></p>

    <p v-if="loading" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="missing" class="notice" role="status">{{ t('error.not_found') }}</p>

    <template v-else-if="scenario">
      <div class="page-head">
        <div>
          <h1>{{ scenario.name }}</h1>
        </div>
        <button v-if="canWrite" class="button button-ghost" type="button" @click="deleting = true">{{ t('common.delete') }}</button>
      </div>

      <p v-if="created" class="notice notice-ok" role="status">{{ t('honeytokens.created') }}</p>
      <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>

      <div class="section panel">
        <dl class="definition">
          <dt>{{ t('field.notes') }}</dt>
          <dd class="notes">{{ scenario.notes === '' ? t('common.none') : scenario.notes }}</dd>
          <dt>{{ t('scenarios.engage') }}</dt>
          <dd><bdi>{{ engageText }}</bdi></dd>
          <dt>{{ t('field.created') }}</dt>
          <dd><TimeStamp :value="scenario.created_at" /></dd>
          <dt>{{ t('field.updated') }}</dt>
          <dd><TimeStamp :value="scenario.updated_at" /></dd>
        </dl>
      </div>

      <div class="section panel">
        <div class="head">
          <h2>{{ t('scenarios.stories') }}</h2>
          <RouterLink v-if="canWrite" class="button button-ghost small" :to="{ name: 'scenario-add-deception', params: { id } }">{{ t('scenarios.addDeception.button') }}</RouterLink>
        </div>
        <p v-if="scenario.deceptions.length === 0" class="hint">{{ canWrite ? t('scenarios.stories.empty') : t('scenarios.stories.emptyRead') }}</p>
        <div v-if="titlesFailed" class="notice notice-error" role="alert">
          {{ t('scenarios.stories.loadFailed') }}
          <button class="button button-ghost small" type="button" @click="loadCatalog">{{ t('scenarios.stories.retry') }}</button>
        </div>
        <ScenarioDeceptionBlock
          v-for="entry in scenario.deceptions"
          :key="entry.deception_id"
          :scenario-id="id"
          :deception-id="entry.deception_id"
          :added-at="entry.created_at"
          :title="titles?.[entry.deception_id]"
          :gone="gone(entry.deception_id)"
          :detail="details[entry.deception_id]"
          :can-remove="canWrite"
          :busy="removing"
          @remove="removeTarget = entry.deception_id"
          @retry="retry(entry.deception_id)"
        />
      </div>

      <ScenarioResources :scenario-id="id" />

      <div v-if="canWrite" class="section panel narrow">
        <h2>{{ t('scenarios.change') }}</h2>
        <p v-if="saved" class="notice notice-ok" role="status">{{ t('common.saved') }}</p>
        <ScenarioForm :key="scenario.updated_at" :existing="scenario" :busy="busy" :submit-label="t('common.save')" @update="update" />
      </div>

      <ConfirmDialog
        v-if="canWrite"
        :open="removeTarget !== undefined"
        neutral
        :title="t('scenarios.stories.removeTitle')"
        :confirm="t('scenarios.stories.removeConfirm')"
        :busy="removing"
        @confirm="removeDeception"
        @cancel="removeTarget = undefined"
      >
        <p>{{ t('scenarios.stories.removeBody') }}</p>
      </ConfirmDialog>

      <ConfirmDialog
        v-if="canWrite"
        :open="deleting"
        :title="t('scenarios.delete.title')"
        :confirm="t('scenarios.delete.confirm')"
        :busy="busy"
        @confirm="remove"
        @cancel="deleting = false"
      >
        <p>{{ t('scenarios.delete.body') }}</p>
        <div v-if="canDeleteResources" class="field">
          <label class="check"><input v-model="withResources" type="checkbox" />{{ t('scenarios.delete.with') }}</label>
          <span class="hint">{{ t('scenarios.delete.withHint') }}</span>
        </div>
      </ConfirmDialog>
    </template>

    <p v-else-if="error" class="notice notice-error" role="alert">{{ error }}</p>
  </section>
</template>

<style scoped>
.notes {
  white-space: pre-wrap;
}

.narrow {
  max-width: 36rem;
}

.head {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  align-items: center;
  justify-content: space-between;
}

.hint {
  color: var(--slate);
}

.check {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}
</style>
