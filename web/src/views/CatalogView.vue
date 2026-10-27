<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue';
import { useRoute } from 'vue-router';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { CatalogArtifactSummary, CatalogDeceptionSummary } from '../api/generated';
import { errorText } from '../api/messages';
import { locale, t } from '../i18n';
import DocsHint from '../components/DocsHint.vue';

type Category = CatalogDeceptionSummary['category'];

const route = useRoute();

// The two tabs are two routes of this page, so that the address and the back link name the one that is open.
const showingArtifacts = computed(() => route.name === 'catalog-artifacts');

// Each tab reads its own list when it is opened. A list in another language than the console shows
// is dropped when the language changes, so that a tab never shows texts of the language before.
const deceptions = ref<CatalogDeceptionSummary[] | undefined>();
const artifacts = ref<CatalogArtifactSummary[] | undefined>();
const error = ref<string | undefined>();
const category = ref<'' | Category>('');

const list = computed<readonly (CatalogDeceptionSummary | CatalogArtifactSummary)[] | undefined>(() => (showingArtifacts.value ? artifacts.value : deceptions.value));
const shown = computed(() => (list.value ?? []).filter((entry) => category.value === '' || entry.category === category.value));

// The catalog is the same in every installation and is not paged. The answer to the last question is the one that counts.
let asked = 0;

async function load(): Promise<void> {
  const mine = ++asked;
  error.value = undefined;
  const query = { lang: locale.value };
  try {
    if (showingArtifacts.value) {
      const body = (await api.call('listCatalogArtifacts', { query })).body.artifacts;
      if (mine === asked) {
        artifacts.value = body;
      }
    } else {
      const body = (await api.call('listCatalogDeceptions', { query })).body.deceptions;
      if (mine === asked) {
        deceptions.value = body;
      }
    }
  } catch (failure) {
    if (mine === asked) {
      error.value = errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
    }
  }
}

onMounted(load);
watch(showingArtifacts, load);
watch(locale, () => {
  if (showingArtifacts.value) {
    deceptions.value = undefined;
  } else {
    artifacts.value = undefined;
  }
  void load();
});
</script>

<template>
  <section>
    <div class="page-head">
      <div>
        <h1>{{ t('catalog.title') }}</h1>
        <DocsHint />
      </div>
    </div>

    <nav class="tabs" :aria-label="t('catalog.tabs')">
      <RouterLink :to="{ name: 'catalog' }" :aria-current="showingArtifacts ? undefined : 'page'">{{ t('catalog.tab.deceptions') }}</RouterLink>
      <RouterLink :to="{ name: 'catalog-artifacts' }" :aria-current="showingArtifacts ? 'page' : undefined">{{ t('catalog.tab.artifacts') }}</RouterLink>
    </nav>
    <p class="hint">{{ showingArtifacts ? t('catalog.tab.artifactsHint') : t('catalog.tab.deceptionsHint') }}</p>

    <div class="toolbar">
      <div class="field">
        <label for="filter-category">{{ t('catalog.filter.category') }}</label>
        <select id="filter-category" v-model="category">
          <option value="">{{ t('common.all') }}</option>
          <option value="identity">{{ t('category.identity') }}</option>
          <option value="network">{{ t('category.network') }}</option>
          <option value="data">{{ t('category.data') }}</option>
          <option value="endpoint">{{ t('category.endpoint') }}</option>
          <option value="application">{{ t('category.application') }}</option>
          <option value="cloud">{{ t('category.cloud') }}</option>
        </select>
      </div>
    </div>

    <p v-if="error" class="notice notice-error" role="alert">{{ t('catalog.loadFailed') }} {{ error }}</p>
    <p v-else-if="list === undefined" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="shown.length === 0" class="notice" role="status">{{ showingArtifacts ? t('catalog.emptyArtifacts') : t('catalog.empty') }}</p>
    <ul v-else class="cards">
      <li v-for="entry in shown" :key="entry.id" class="card panel">
        <p><span class="badge">{{ t(`category.${entry.category}`) }}</span></p>
        <h2>
          <RouterLink :to="showingArtifacts ? { name: 'catalog-artifact', params: { id: entry.id } } : { name: 'catalog-deception', params: { id: entry.id } }">{{ entry.title }}</RouterLink>
        </h2>
        <p>{{ entry.summary }}</p>
        <p v-if="'techniques' in entry" class="ids mono">{{ entry.techniques.join(', ') }}</p>
      </li>
    </ul>
  </section>
</template>

<style scoped>
.tabs {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
  margin-bottom: 0.6rem;
}

.tabs a {
  padding: 0.35rem 0.9rem;
  border: 1px solid var(--line);
  border-radius: var(--radius-sm);
  background: var(--surface-raised);
  color: var(--ink);
  text-decoration: none;
}

.tabs a[aria-current='page'] {
  border-color: var(--mint);
  background: var(--mint-soft);
  font-weight: 600;
}

.hint {
  color: var(--slate);
  font-size: 0.8125rem;
}

.cards {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(18rem, 1fr));
  gap: 1rem;
  margin: 0;
  padding: 0;
  list-style: none;
}

.card {
  display: grid;
  gap: 0.6rem;
  align-content: start;
  padding: 1.1rem;
}

.card h2 {
  font-size: 1.05rem;
}

.ids {
  color: var(--slate);
  font-size: 0.8125rem;
}
</style>
