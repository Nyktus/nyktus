<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { Artifact, Honeypot, Honeytoken, OperationTypes, Scenario } from '../api/generated';
import { errorText } from '../api/messages';
import ConfirmDialog from '../components/ConfirmDialog.vue';
import FileSize from '../components/FileSize.vue';
import MarkdownView from '../components/MarkdownView';
import ScenarioForm from '../components/ScenarioForm.vue';
import SeverityBadge from '../components/SeverityBadge.vue';
import StateBadge from '../components/StateBadge.vue';
import TimeStamp from '../components/TimeStamp.vue';
import { carriesHoneytoken } from '../artifactRole';
import { t } from '../i18n';
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
const choice = reactive<{ honeytokens: 'keep' | 'delete'; honeypots: 'keep' | 'delete'; artifacts: 'keep' | 'delete' }>({
  honeytokens: 'keep',
  honeypots: 'keep',
  artifacts: 'keep',
});

// Whatever closes the dialog, the next one starts with keeping: a choice to delete that was
// made and given up must not be the one that a later click on "Delete" carries out.
watch(deleting, () => {
  choice.honeytokens = 'keep';
  choice.honeypots = 'keep';
  choice.artifacts = 'keep';
});

const detaching = ref(false);

const guides = ref<{ deception_id: string; language: string; content: string }[]>([]);
const guideFailed = ref(false);
const guidesLoaded = ref(false);

const honeytokens = usePagedList<Honeytoken>(async (cursor) => {
  const { body } = await api.call('listHoneytokens', { query: { limit: 50, cursor, scenario_id: id.value } });
  return { items: body.honeytokens, next: body.next_cursor };
});
const artifacts = usePagedList<Artifact>(async (cursor) => {
  const { body } = await api.call('listArtifacts', { query: { limit: 50, cursor, scenario_id: id.value } });
  return { items: body.artifacts, next: body.next_cursor };
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
    void artifacts.reload();
    void loadGuide();
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

// Only a scenario with a deception has guides; one put together by hand has none.
async function loadGuide(): Promise<void> {
  guides.value = [];
  guideFailed.value = false;
  guidesLoaded.value = false;
  if (scenario.value?.deceptions.length === 0) {
    return;
  }
  try {
    guides.value = (await api.call('getScenarioGuide', { path: { id: id.value } })).body.guides;
    guidesLoaded.value = true;
  } catch {
    guideFailed.value = true;
  }
}

function guideOf(deceptionId: string): string | undefined {
  return guides.value.find((g) => g.deception_id === deceptionId)?.content;
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
    if (choice.artifacts === 'delete') {
      query.artifacts = 'delete';
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
          <template v-if="Object.keys(scenario.persona).length > 0">
            <dt>{{ t('scenarios.persona') }}</dt>
            <dd>
              <dl class="persona">
                <template v-for="(value, key) in scenario.persona" :key="key">
                  <dt class="mono">{{ key }}</dt>
                  <dd><bdi>{{ value }}</bdi></dd>
                </template>
              </dl>
            </dd>
          </template>
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
        <p v-if="guideFailed" class="notice notice-error" role="alert">{{ t('scenarios.guideFailed') }}</p>
        <article v-for="story in scenario.deceptions" :key="story.deception_id" class="story">
          <h3>
            <RouterLink class="mono" :to="{ name: 'catalog-deception', params: { id: story.deception_id } }">{{ story.deception_id }}</RouterLink>
          </h3>
          <p class="hint">{{ t('scenarios.stories.added') }} <TimeStamp :value="story.created_at" /></p>
          <details :open="scenario.deceptions.length === 1">
            <summary>{{ t('scenarios.guide') }}</summary>
            <MarkdownView v-if="guideOf(story.deception_id) !== undefined" :source="guideOf(story.deception_id) ?? ''" />
            <p v-else-if="!guideFailed && !guidesLoaded" role="status">{{ t('app.loading') }}</p>
          </details>
        </article>
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

      <div class="section panel">
        <div class="head">
          <h2>{{ t('artifacts.ofScenario') }}</h2>
          <RouterLink v-if="canWrite" class="button button-ghost small" :to="{ name: 'scenario-add-artifact', params: { id } }">{{ t('scenarios.addArtifact.button') }}</RouterLink>
        </div>
        <p v-if="artifacts.error.value" class="notice notice-error" role="alert">{{ t('artifacts.loadFailed') }}</p>
        <p v-else-if="!artifacts.loaded.value && artifacts.items.value.length === 0" role="status">{{ t('app.loading') }}</p>
        <p v-else-if="artifacts.loaded.value && artifacts.items.value.length === 0" class="hint">{{ canWrite ? t('artifacts.noneHere') : t('artifacts.none') }}</p>
        <template v-else-if="artifacts.items.value.length > 0">
          <p class="hint">{{ t('artifacts.roleHint') }}</p>
          <div class="table-wrap">
            <table class="table">
              <tbody>
                <tr v-for="artifact in artifacts.items.value" :key="artifact.id">
                  <td><RouterLink class="mono" :to="{ name: 'artifact', params: { id: artifact.id } }"><bdi>{{ artifact.file_name }}</bdi></RouterLink></td>
                  <td>{{ t(`artifactFormat.${artifact.format}`) }}</td>
                  <td>{{ carriesHoneytoken(artifact) ? t('artifacts.role.lure') : t('artifacts.role.litter') }}</td>
                  <td><FileSize :bytes="artifact.size" /></td>
                </tr>
              </tbody>
            </table>
          </div>
        </template>
        <p v-if="artifacts.next.value !== undefined">
          <button class="button button-ghost small" type="button" :disabled="artifacts.loading.value" @click="artifacts.more">{{ t('common.loadMore') }}</button>
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
        <fieldset v-for="kind in (['honeytokens', 'honeypots', 'artifacts'] as const)" v-show="kind !== 'honeypots' || canWriteHoneypots" :key="kind" class="choice">
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

.persona {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 0.2rem 1rem;
  margin: 0;
}

.persona dd {
  margin: 0;
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
