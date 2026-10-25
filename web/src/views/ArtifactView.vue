<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { Artifact } from '../api/generated';
import { errorText } from '../api/messages';
import ConfirmDialog from '../components/ConfirmDialog.vue';
import FileSize from '../components/FileSize.vue';
import TimeStamp from '../components/TimeStamp.vue';
import { saveFile } from '../download';
import { formatSize } from '../format';
import { locale, t } from '../i18n';
import { session } from '../session';

/** How much of a file the page shows as text; the file is at most 1 MiB. */
const previewLimit = 64 * 1024;

const route = useRoute();
const router = useRouter();

const id = computed(() => String(route.params.id));
const artifact = ref<Artifact | undefined>();
const loading = ref(true);
const missing = ref(false);
const error = ref<string | undefined>();
const saved = ref(false);
const busy = ref(false);
const deleting = ref(false);
const notes = ref('');
const preview = ref<{ text: string; cut: boolean } | undefined>();
const previewing = ref(false);
const canWrite = computed(() => session.can('artifacts:write'));
// Only text is shown, and as text; a file that is not text is only downloaded.
const previewable = computed(() => artifact.value !== undefined && artifact.value.media_type.startsWith('text/'));

function show(failure: unknown): string {
  return errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
}

async function load(): Promise<void> {
  loading.value = true;
  error.value = undefined;
  try {
    artifact.value = (await api.call('getArtifact', { path: { id: id.value } })).body;
    notes.value = artifact.value.placement_notes;
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

async function fetchFile(): Promise<Blob> {
  return (await api.call('downloadArtifact', { path: { id: id.value } })).body;
}

async function download(): Promise<void> {
  if (artifact.value === undefined) {
    return;
  }
  error.value = undefined;
  try {
    saveFile(await fetchFile(), artifact.value.file_name);
  } catch (failure) {
    error.value = `${t('artifacts.downloadFailed')} ${show(failure)}`;
  }
}

async function togglePreview(): Promise<void> {
  if (preview.value !== undefined) {
    preview.value = undefined;
    return;
  }
  error.value = undefined;
  previewing.value = true;
  try {
    const blob = await fetchFile();
    const cut = blob.size > previewLimit;
    // The cut may fall in the middle of a character; what is left of it is not shown as a replacement.
    const bytes = new Uint8Array(await blob.slice(0, previewLimit).arrayBuffer());
    preview.value = { text: new TextDecoder().decode(bytes, { stream: true }), cut };
  } catch (failure) {
    error.value = show(failure);
  } finally {
    previewing.value = false;
  }
}

async function saveNotes(): Promise<void> {
  saved.value = false;
  error.value = undefined;
  if (artifact.value === undefined || notes.value === artifact.value.placement_notes) {
    saved.value = true;
    return;
  }
  busy.value = true;
  try {
    artifact.value = (await api.call('updateArtifact', { path: { id: id.value }, body: { placement_notes: notes.value } })).body;
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
    await api.call('deleteArtifact', { path: { id: id.value } });
    await router.replace({ name: 'artifacts' });
  } catch (failure) {
    deleting.value = false;
    error.value = show(failure);
  } finally {
    busy.value = false;
  }
}

function cutSize(): string {
  return t('unit.kib', { count: formatSize(previewLimit, locale.value).count });
}

onMounted(load);
</script>

<template>
  <section>
    <p><RouterLink :to="{ name: 'artifacts' }">{{ t('artifacts.back') }}</RouterLink></p>

    <p v-if="loading" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="missing" class="notice" role="status">{{ t('error.not_found') }}</p>

    <template v-else-if="artifact">
      <div class="page-head">
        <div>
          <h1 class="mono name">{{ artifact.file_name }}</h1>
          <p class="badges">
            <span class="badge">{{ t(`artifactFormat.${artifact.format}`) }}</span>
          </p>
        </div>
        <div class="actions-row">
          <button class="button button-primary" type="button" @click="download">{{ t('artifacts.download') }}</button>
          <button v-if="canWrite" class="button button-ghost" type="button" @click="deleting = true">{{ t('common.delete') }}</button>
        </div>
      </div>

      <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>

      <div class="section panel">
        <dl class="definition">
          <dt>{{ t('artifacts.size') }}</dt>
          <dd><FileSize :bytes="artifact.size" /></dd>
          <dt>{{ t('artifacts.mediaType') }}</dt>
          <dd class="mono">{{ artifact.media_type }}</dd>
          <dt>{{ t('artifacts.scenario') }}</dt>
          <dd>
            <RouterLink v-if="artifact.scenario_id" :to="{ name: 'scenario', params: { id: artifact.scenario_id } }">{{ t('artifacts.scenario') }}</RouterLink>
            <template v-else>{{ t('artifacts.scenarioGone') }}</template>
          </dd>
          <dt>{{ t('artifacts.key') }}</dt>
          <dd class="mono">{{ artifact.catalog_artifact }}</dd>
          <dt>{{ t('artifacts.placement') }}</dt>
          <dd class="notes">{{ artifact.placement_notes === '' ? t('common.none') : artifact.placement_notes }}</dd>
          <dt>{{ t('field.created') }}</dt>
          <dd><TimeStamp :value="artifact.created_at" /></dd>
          <dt>{{ t('field.updated') }}</dt>
          <dd><TimeStamp :value="artifact.updated_at" /></dd>
        </dl>
      </div>

      <div class="section panel">
        <h2>{{ t('artifacts.preview') }}</h2>
        <p v-if="!previewable" class="hint">{{ t('artifacts.noPreview') }}</p>
        <template v-else>
          <p class="hint">{{ t('artifacts.previewNote') }}</p>
          <p>
            <button class="button button-ghost small" type="button" :disabled="previewing" @click="togglePreview">
              {{ preview ? t('artifacts.previewHide') : t('artifacts.preview') }}
            </button>
          </p>
          <template v-if="preview">
            <pre class="mono content">{{ preview.text }}</pre>
            <p v-if="preview.cut" class="hint">{{ t('artifacts.previewCut', { size: cutSize() }) }}</p>
          </template>
        </template>
      </div>

      <div v-if="canWrite" class="section panel narrow">
        <h2>{{ t('artifacts.placement') }}</h2>
        <p v-if="saved" class="notice notice-ok" role="status">{{ t('common.saved') }}</p>
        <form class="stack" @submit.prevent="saveNotes">
          <div class="field">
            <label for="placement">{{ t('artifacts.placement') }}</label>
            <textarea id="placement" v-model="notes" maxlength="2000" aria-describedby="placement-hint"></textarea>
            <span id="placement-hint" class="hint">{{ t('artifacts.placementHint') }}</span>
          </div>
          <div class="actions-row">
            <button class="button button-primary" type="submit" :disabled="busy">{{ busy ? t('app.saving') : t('common.save') }}</button>
          </div>
        </form>
      </div>

      <ConfirmDialog
        v-if="canWrite"
        :open="deleting"
        :title="t('artifacts.delete.title')"
        :confirm="t('artifacts.delete.confirm')"
        :busy="busy"
        @confirm="remove"
        @cancel="deleting = false"
      >
        {{ t('artifacts.delete.body') }}
      </ConfirmDialog>
    </template>

    <p v-else-if="error" class="notice notice-error" role="alert">{{ error }}</p>
  </section>
</template>

<style scoped>
.name {
  overflow-wrap: anywhere;
}

.badges {
  margin-top: 0.5rem;
}

.notes {
  white-space: pre-wrap;
}

.narrow {
  max-width: 36rem;
}

.hint {
  color: var(--slate);
  font-size: 0.8125rem;
}

.content {
  margin: 0;
  padding: 0.7rem 0.9rem;
  max-height: 32rem;
  overflow: auto;
  border-radius: var(--radius-sm);
  background: var(--ink);
  color: #e2e9e5;
  font-size: 0.8125rem;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
</style>
