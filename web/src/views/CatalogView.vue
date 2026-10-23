<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { CatalogDeceptionSummary } from '../api/generated';
import { errorText } from '../api/messages';
import { locale, t } from '../i18n';

const deceptions = ref<CatalogDeceptionSummary[]>([]);
const loaded = ref(false);
const error = ref<string | undefined>();
const category = ref<'' | CatalogDeceptionSummary['category']>('');

const shown = computed(() => deceptions.value.filter((d) => category.value === '' || d.category === category.value));

// The catalog is the same in every installation and is not paged.
async function load(): Promise<void> {
  error.value = undefined;
  try {
    deceptions.value = (await api.call('listCatalogDeceptions', { query: { lang: locale.value } })).body.deceptions;
    loaded.value = true;
  } catch (failure) {
    error.value = errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
  }
}

onMounted(load);
watch(locale, load);
</script>

<template>
  <section>
    <div class="page-head">
      <div>
        <h1>{{ t('catalog.title') }}</h1>
        <p class="lede">{{ t('catalog.intro') }}</p>
      </div>
    </div>

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
        </select>
      </div>
    </div>

    <p v-if="error" class="notice notice-error" role="alert">{{ t('catalog.loadFailed') }} {{ error }}</p>
    <p v-else-if="!loaded" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="shown.length === 0" class="notice" role="status">{{ t('catalog.empty') }}</p>
    <ul v-else class="cards">
      <li v-for="deception in shown" :key="deception.id" class="card panel">
        <p><span class="badge">{{ t(`category.${deception.category}`) }}</span></p>
        <h2>
          <RouterLink :to="{ name: 'catalog-deception', params: { id: deception.id } }">{{ deception.title }}</RouterLink>
        </h2>
        <p>{{ deception.summary }}</p>
        <p class="ids mono">{{ deception.techniques.join(', ') }}</p>
      </li>
    </ul>
  </section>
</template>

<style scoped>
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
