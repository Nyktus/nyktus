<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { onMounted } from 'vue';
import { api } from '../api/client';
import type { Artifact } from '../api/generated';
import DocsHint from '../components/DocsHint.vue';
import FileSize from '../components/FileSize.vue';
import TimeStamp from '../components/TimeStamp.vue';
import { t } from '../i18n';
import { usePagedList } from '../usePagedList';

const list = usePagedList<Artifact>(async (cursor) => {
  const { body } = await api.call('listArtifacts', { query: { limit: 50, cursor } });
  return { items: body.artifacts, next: body.next_cursor };
});

onMounted(list.reload);
</script>

<template>
  <section>
    <div class="page-head">
      <div>
        <h1>{{ t('artifacts.title') }}</h1>
        <DocsHint />
      </div>
    </div>

    <p v-if="list.error.value" class="notice notice-error" role="alert">{{ t('artifacts.loadFailed') }} {{ list.error.value }}</p>

    <p v-if="!list.loaded.value && list.loading.value" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="list.loaded.value && list.items.value.length === 0" class="notice" role="status">{{ t('artifacts.empty') }}</p>
    <div v-else-if="list.items.value.length > 0" class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th scope="col">{{ t('artifacts.fileName') }}</th>
            <th scope="col">{{ t('artifacts.format') }}</th>
            <th scope="col">{{ t('artifacts.role') }}</th>
            <th scope="col">{{ t('artifacts.size') }}</th>
            <th scope="col">{{ t('field.created') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="artifact in list.items.value" :key="artifact.id">
            <td>
              <RouterLink class="mono" :to="{ name: 'artifact', params: { id: artifact.id } }"><bdi>{{ artifact.file_name }}</bdi></RouterLink>
            </td>
            <td>{{ t(`artifactFormat.${artifact.format}`) }}</td>
            <td>{{ Object.keys(artifact.bindings).length > 0 ? t('artifacts.role.lure') : t('artifacts.role.litter') }}</td>
            <td><FileSize :bytes="artifact.size" /></td>
            <td><TimeStamp :value="artifact.created_at" /></td>
          </tr>
        </tbody>
      </table>
    </div>

    <p v-if="list.next.value !== undefined" class="actions-row more">
      <button class="button button-ghost" type="button" :disabled="list.loading.value" @click="list.more">{{ t('common.loadMore') }}</button>
    </p>
  </section>
</template>

<style scoped>
.more {
  margin-top: 1rem;
}
</style>
