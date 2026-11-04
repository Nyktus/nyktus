<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { CatalogDeception, Honeypot, Honeytoken, OperationTypes, Scenario } from '../api/generated';
import { errorText } from '../api/messages';
import ConfirmDialog from '../components/ConfirmDialog.vue';
import DeceptionDetail from '../components/DeceptionDetail.vue';
import ScenarioForm from '../components/ScenarioForm.vue';
import SeverityBadge from '../components/SeverityBadge.vue';
import StateBadge from '../components/StateBadge.vue';
import TimeStamp from '../components/TimeStamp.vue';
import { locale, t } from '../i18n';
import { session } from '../session';
import { usePagedList } from '../usePagedList';

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
const canWrite = computed(() => session.can('scenarios:write'));
const canWriteHoneytokens = computed(() => session.can('honeytokens:write'));
const canWriteHoneypots = computed(() => session.can('honeypots:write'));

// What happens to the decoys when the scenario is deleted. Keeping them is the safe choice.
const choice = reactive<{ honeytokens: 'keep' | 'delete'; honeypots: 'keep' | 'delete' }>({
  honeytokens: 'keep',
  honeypots: 'keep',
});

// Whatever closes the dialog, the next one starts with keeping: a choice to delete that was
// made and given up must not be the one that a later click on "Delete" carries out.
watch(deleting, () => {
  choice.honeytokens = 'keep';
  choice.honeypots = 'keep';
});

const detaching = ref(false);

// The titles of the deceptions come from the list of the catalog, in the language of the console, in one request.
// A deception that the list lacks is gone from the catalog. The guide, the slots and the files of a deception are
// read when its section is opened, and again when the language changes; one that could not be read is asked for
// again the next time the section is opened.
const titles = ref<Record<string, string> | undefined>();
const titlesFailed = ref(false);
const details = ref<Record<string, CatalogDeception | 'failed'>>({});
const opened = new Set<string>();
// What is being asked for, by language and deception, so that a question in another language is not skipped.
const asking = new Set<string>();
const removing = ref(false);

const honeytokens = usePagedList<Honeytoken>(async (cursor) => {
  const { body } = await api.call('listHoneytokens', { query: { limit: 50, cursor, scenario_id: id.value } });
  return { items: body.honeytokens, next: body.next_cursor };
});
const honeypots = usePagedList<Honeypot>(async (cursor) => {
  const { body } = await api.call('listHoneypots', { query: { limit: 50, cursor, scenario_id: id.value } });
  return { items: body.honeypots, next: body.next_cursor };
});

function show(failure: unknown): string {
  return errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
}

async function load(): Promise<void> {
  loading.value = true;
  error.value = undefined;
  try {
    scenario.value = (await api.call('getScenario', { path: { id: id.value } })).body;
    void honeytokens.reload();
    void honeypots.reload();
    void loadTitles();
    // A single deception is shown open, so its guide is read at once.
    if (scenario.value.deceptions.length === 1) {
      openSection(scenario.value.deceptions[0]?.deception_id ?? '');
    }
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

// The answer of the last question is the one that counts, also when the language changes meanwhile.
let askedTitles = 0;

async function loadTitles(): Promise<void> {
  const mine = ++askedTitles;
  titlesFailed.value = false;
  // Without the scenario there is nothing to name yet, and one without deceptions has no titles to read.
  if (scenario.value === undefined || scenario.value.deceptions.length === 0) {
    return;
  }
  try {
    const list = (await api.call('listCatalogDeceptions', { query: { lang: locale.value } })).body.deceptions;
    if (mine === askedTitles) {
      titles.value = Object.fromEntries(list.map((entry) => [entry.id, entry.title]));
    }
  } catch {
    if (mine === askedTitles) {
      titlesFailed.value = true;
    }
  }
}

async function loadDetail(deceptionId: string): Promise<void> {
  const language = locale.value;
  const question = `${language}/${deceptionId}`;
  if (asking.has(question)) {
    return;
  }
  asking.add(question);
  try {
    const body = (await api.call('getCatalogDeception', { path: { id: deceptionId }, query: { lang: language } })).body;
    if (language === locale.value) {
      details.value = { ...details.value, [deceptionId]: body };
    }
  } catch {
    if (language === locale.value) {
      details.value = { ...details.value, [deceptionId]: 'failed' };
    }
  } finally {
    asking.delete(question);
  }
}

function openSection(deceptionId: string): void {
  opened.add(deceptionId);
  const found = details.value[deceptionId];
  if (found === undefined || found === 'failed') {
    void loadDetail(deceptionId);
  }
}

function toggle(deceptionId: string, event: Event): void {
  if ((event.target as HTMLDetailsElement).open) {
    openSection(deceptionId);
  } else {
    opened.delete(deceptionId);
  }
}

function detail(deceptionId: string): CatalogDeception | undefined {
  const found = details.value[deceptionId];
  return typeof found === 'object' ? found : undefined;
}

// The catalog lacks a deception that its list does not name, once the list has been read.
function gone(deceptionId: string): boolean {
  return titles.value !== undefined && !(deceptionId in titles.value);
}

// The language changes what the catalog says, so what was read in the other one is dropped.
function reloadForLanguage(): void {
  details.value = {};
  titles.value = undefined;
  void loadTitles();
  for (const deceptionId of opened) {
    void loadDetail(deceptionId);
  }
}

// Removing a deception ends the assignment only; its honeytokens and honeypots stay in the scenario.
async function removeDeception(deceptionId: string): Promise<void> {
  removing.value = true;
  error.value = undefined;
  try {
    scenario.value = (await api.call('removeScenarioDeception', { path: { id: id.value, deception_id: deceptionId } })).body;
    opened.delete(deceptionId);
  } catch (failure) {
    error.value = show(failure);
  } finally {
    removing.value = false;
  }
}

async function update(body: OperationTypes['updateScenario']['body']): Promise<void> {
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

async function detach(kind: 'honeytoken' | 'honeypot', resourceId: string): Promise<void> {
  detaching.value = true;
  error.value = undefined;
  try {
    if (kind === 'honeytoken') {
      await api.call('detachHoneytokenScenario', { path: { id: resourceId } });
      await honeytokens.reload();
    } else {
      await api.call('detachHoneypotScenario', { path: { id: resourceId } });
      await honeypots.reload();
    }
  } catch (failure) {
    error.value = show(failure);
  } finally {
    detaching.value = false;
  }
}

async function remove(): Promise<void> {
  busy.value = true;
  try {
    // Keeping is what the server does without a parameter, so only deleting is asked for.
    const query: OperationTypes['deleteScenario']['query'] = {};
    if (choice.honeytokens === 'delete') {
      query.honeytokens = 'delete';
    }
    if (choice.honeypots === 'delete' && canWriteHoneypots.value) {
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

onMounted(load);
watch(locale, reloadForLanguage);
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

      <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>

      <div class="section panel">
        <dl class="definition">
          <dt>{{ t('field.notes') }}</dt>
          <dd class="notes">{{ scenario.notes === '' ? t('common.none') : scenario.notes }}</dd>
          <dt>{{ t('scenarios.engage') }}</dt>
          <dd class="mono">{{ scenario.engage_activities.length === 0 ? t('common.none') : scenario.engage_activities.join(', ') }}</dd>
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
        <p v-if="titlesFailed" class="notice notice-error" role="alert">{{ t('scenarios.stories.loadFailed') }}</p>
        <article v-for="entry in scenario.deceptions" :key="entry.deception_id" class="story">
          <div class="head">
            <h3>
              <span v-if="gone(entry.deception_id)" class="mono">{{ entry.deception_id }}</span>
              <RouterLink v-else class="mono" :to="{ name: 'catalog-deception', params: { id: entry.deception_id } }">
                {{ titles?.[entry.deception_id] ?? entry.deception_id }}
              </RouterLink>
            </h3>
            <button v-if="canWrite" class="button button-ghost small" type="button" :disabled="removing" @click="removeDeception(entry.deception_id)">
              {{ t('scenarios.stories.remove') }}
            </button>
          </div>
          <p class="hint">{{ t('scenarios.stories.added') }} <TimeStamp :value="entry.created_at" /></p>
          <p v-if="gone(entry.deception_id)" class="notice" role="status">{{ t('scenarios.stories.gone') }}</p>
          <details v-else :open="scenario.deceptions.length === 1" @toggle="toggle(entry.deception_id, $event)">
            <summary>{{ t('scenarios.guide') }}</summary>
            <DeceptionDetail v-if="detail(entry.deception_id)" :deception="detail(entry.deception_id) as CatalogDeception" :under="3" />
            <p v-else-if="details[entry.deception_id] === 'failed'" class="notice notice-error" role="alert">{{ t('scenarios.stories.loadFailed') }}</p>
            <p v-else role="status">{{ t('app.loading') }}</p>
          </details>
        </article>
        <p v-if="canWrite && scenario.deceptions.length > 0" class="hint">{{ t('scenarios.stories.removeHint') }}</p>
      </div>

      <div class="section panel">
        <div class="head">
          <h2>{{ t('scenarios.members.honeytokens') }}</h2>
          <RouterLink v-if="canWriteHoneytokens" class="button button-ghost small" :to="{ name: 'honeytoken-new', query: { scenario: id } }">
            {{ t('scenarios.members.addHoneytoken') }}
          </RouterLink>
        </div>
        <p v-if="honeytokens.error.value" class="notice notice-error" role="alert">{{ t('scenarios.members.loadFailed') }}</p>
        <p v-else-if="honeytokens.loaded.value && honeytokens.items.value.length === 0" class="hint">{{ t('scenarios.members.none') }}</p>
        <div v-else-if="honeytokens.items.value.length > 0" class="table-wrap">
          <table class="table">
            <tbody>
              <tr v-for="honeytoken in honeytokens.items.value" :key="honeytoken.id">
                <td><RouterLink :to="{ name: 'honeytoken', params: { id: honeytoken.id } }">{{ honeytoken.name }}</RouterLink></td>
                <td>{{ t(`honeytokenType.${honeytoken.type}`) }}</td>
                <td><StateBadge :enabled="honeytoken.enabled" /></td>
                <td><SeverityBadge :severity="honeytoken.severity" /></td>
                <td class="end">
                  <button v-if="canWriteHoneytokens" class="button button-ghost small" type="button" :disabled="detaching" @click="detach('honeytoken', honeytoken.id)">
                    {{ t('scenarios.remove') }}
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <p v-if="honeytokens.next.value !== undefined">
          <button class="button button-ghost small" type="button" :disabled="honeytokens.loading.value" @click="honeytokens.more">{{ t('common.loadMore') }}</button>
        </p>
      </div>

      <div class="section panel">
        <div class="head">
          <h2>{{ t('scenarios.members.honeypots') }}</h2>
          <RouterLink v-if="canWriteHoneypots" class="button button-ghost small" :to="{ name: 'honeypot-new', query: { scenario: id } }">
            {{ t('scenarios.members.addHoneypot') }}
          </RouterLink>
        </div>
        <p v-if="honeypots.error.value" class="notice notice-error" role="alert">{{ t('scenarios.members.loadFailed') }}</p>
        <p v-else-if="honeypots.loaded.value && honeypots.items.value.length === 0" class="hint">{{ t('scenarios.members.none') }}</p>
        <div v-else-if="honeypots.items.value.length > 0" class="table-wrap">
          <table class="table">
            <tbody>
              <tr v-for="honeypot in honeypots.items.value" :key="honeypot.id">
                <td><RouterLink :to="{ name: 'honeypot', params: { id: honeypot.id } }">{{ honeypot.name }}</RouterLink></td>
                <td>{{ t(`honeypotService.${honeypot.service}`) }}</td>
                <td><StateBadge :enabled="honeypot.enabled" /></td>
                <td><SeverityBadge :severity="honeypot.severity" /></td>
                <td class="end">
                  <button v-if="canWriteHoneypots" class="button button-ghost small" type="button" :disabled="detaching" @click="detach('honeypot', honeypot.id)">
                    {{ t('scenarios.remove') }}
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <p v-if="honeypots.next.value !== undefined">
          <button class="button button-ghost small" type="button" :disabled="honeypots.loading.value" @click="honeypots.more">{{ t('common.loadMore') }}</button>
        </p>
      </div>

      <div v-if="canWrite" class="section panel narrow">
        <h2>{{ t('scenarios.change') }}</h2>
        <p v-if="saved" class="notice notice-ok" role="status">{{ t('common.saved') }}</p>
        <ScenarioForm :key="scenario.updated_at" :existing="scenario" :busy="busy" :submit-label="t('common.save')" @update="update" />
      </div>

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
        <fieldset v-for="kind in (['honeytokens', 'honeypots'] as const)" v-show="kind !== 'honeypots' || canWriteHoneypots" :key="kind" class="choice">
          <legend>{{ t(`scenarios.delete.${kind}`) }}</legend>
          <label><input v-model="choice[kind]" type="radio" :name="`delete-${kind}`" value="keep" />{{ t('scenarios.delete.keep') }}</label>
          <label><input v-model="choice[kind]" type="radio" :name="`delete-${kind}`" value="delete" />{{ t('scenarios.delete.delete') }}</label>
        </fieldset>
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

.end {
  text-align: right;
}

.head {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  align-items: center;
  justify-content: space-between;
}

.story {
  margin-top: 0.9rem;
  padding-top: 0.9rem;
  border-top: 1px solid var(--line-soft);
}

.story h3 {
  font-size: 0.95rem;
}

.story summary {
  cursor: pointer;
  font-weight: 600;
}

.hint {
  color: var(--slate);
}

.choice {
  display: grid;
  gap: 0.3rem;
  margin: 0.75rem 0 0;
  padding: 0.5rem 0.75rem;
  border: 1px solid var(--line);
  border-radius: var(--radius-sm);
}

.choice legend {
  padding: 0 0.3rem;
  font-weight: 600;
}

.choice label {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}
</style>
