<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue';
import { useRoute } from 'vue-router';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { CatalogArtifact } from '../api/generated';
import { errorText } from '../api/messages';
import { locale, t } from '../i18n';

const route = useRoute();

const id = computed(() => String(route.params.id));
const artifact = ref<CatalogArtifact | undefined>();
const loading = ref(true);
const missing = ref(false);
const loadError = ref<string | undefined>();

// Whether the file can be pocket litter depends on its slots: a required slot always carries a honeytoken.
const carriesAlways = computed(() => artifact.value?.slots.some((slot) => !slot.optional) ?? false);

// A change of the language asks again; the answer of the last question is the one that counts.
let asked = 0;

async function load(): Promise<void> {
  const mine = ++asked;
  loadError.value = undefined;
  try {
    const body = (await api.call('getCatalogArtifact', { path: { id: id.value }, query: { lang: locale.value } })).body;
    if (mine === asked) {
      artifact.value = body;
    }
  } catch (failure) {
    if (mine !== asked) {
      return;
    }
    if (failure instanceof ApiError && failure.kind === 'not_found') {
      missing.value = true;
    } else {
      loadError.value = errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
    }
  } finally {
    if (mine === asked) {
      loading.value = false;
    }
  }
}

onMounted(load);
watch(locale, load);
</script>

<template>
  <section>
    <p><RouterLink :to="{ name: 'catalog-artifacts' }">{{ t('catalog.artifact.back') }}</RouterLink></p>

    <p v-if="loading" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="missing" class="notice" role="status">{{ t('error.not_found') }}</p>

    <template v-else-if="artifact">
      <p v-if="loadError" class="notice notice-error" role="alert">{{ loadError }}</p>
      <div class="page-head">
        <div>
          <h1>{{ artifact.title }}</h1>
          <p class="lede">{{ artifact.summary }}</p>
          <p class="badges"><span class="badge">{{ t(`category.${artifact.category}`) }}</span></p>
        </div>
      </div>

      <div class="section panel">
        <dl class="definition">
          <dt>{{ t('artifacts.fileName') }}</dt>
          <dd class="mono"><bdi>{{ artifact.file_name }}</bdi></dd>
          <dt>{{ t('artifacts.format') }}</dt>
          <dd>{{ t(`artifactFormat.${artifact.format}`) }}</dd>
          <dt>{{ t('catalog.secrets') }}</dt>
          <dd>{{ artifact.secrets.length === 0 ? t('common.none') : t('catalog.secretsValue', { count: artifact.secrets.length }) }}</dd>
        </dl>
      </div>

      <div class="section panel">
        <h2>{{ t('catalog.artifact.slots') }}</h2>
        <p v-if="artifact.slots.length === 0" class="hint">{{ t('catalog.artifact.noSlots') }}</p>
        <template v-else>
          <p class="hint">{{ carriesAlways ? t('catalog.artifact.alwaysLure') : t('catalog.artifact.maybeLitter') }}</p>
          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>{{ t('catalog.artifact.slot') }}</th>
                  <th>{{ t('catalog.artifact.accepts') }}</th>
                  <th>{{ t('catalog.artifact.need') }}</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="slot in artifact.slots" :key="slot.key">
                  <td class="mono">{{ slot.key }}</td>
                  <td>{{ slot.accepts.map((type) => t(`honeytokenType.${type}`)).join(', ') }}</td>
                  <td>{{ slot.optional ? t('catalog.artifact.optional') : t('catalog.artifact.required') }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </template>
      </div>

      <div v-if="artifact.persona.length > 0" class="section panel">
        <h2>{{ t('catalog.artifact.persona') }}</h2>
        <p class="hint">{{ t('catalog.artifact.personaHint') }}</p>
        <div class="table-wrap">
          <table class="table">
            <tbody>
              <tr v-for="field in artifact.persona" :key="field.key">
                <td>{{ field.label }}</td>
                <td>{{ t(`persona.${field.kind}`) }}</td>
                <td class="hint">{{ t('persona.example', { example: field.example }) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <p class="hint">
        {{ t('catalog.artifact.addHint') }}
        <RouterLink :to="{ name: 'scenarios' }">{{ t('scenarios.title') }}</RouterLink>
      </p>
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
</style>
