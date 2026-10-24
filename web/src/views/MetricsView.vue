<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import { errorText } from '../api/messages';
import DocsHint from '../components/DocsHint.vue';
import TimeStamp from '../components/TimeStamp.vue';
import { t } from '../i18n';
import { parseMetrics, type Family } from '../metrics';

const raw = ref<string | undefined>();
const loading = ref(false);
const error = ref<string | undefined>();

const parsed = computed(() => (raw.value === undefined ? undefined : parseMetrics(raw.value)));

async function load(): Promise<void> {
  loading.value = true;
  error.value = undefined;
  try {
    raw.value = await (await api.call('getMetrics', {})).body.text();
  } catch (failure) {
    error.value = errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
  } finally {
    loading.value = false;
  }
}

/** A time that a metric reports as seconds since the epoch, for the metrics named so. */
function moment(family: Family, value: string): string | undefined {
  const seconds = Number(value);
  if (!family.name.endsWith('_timestamp_seconds') || !Number.isFinite(seconds) || seconds <= 0) {
    return undefined;
  }
  const time = new Date(seconds * 1000);
  return Number.isNaN(time.getTime()) ? undefined : time.toISOString();
}

onMounted(load);
</script>

<template>
  <section>
    <div class="page-head">
      <div>
        <h1>{{ t('metrics.title') }}</h1>
        <DocsHint />
      </div>
      <button class="button button-ghost" type="button" :disabled="loading" @click="load">{{ t('common.refresh') }}</button>
    </div>

    <p v-if="error" class="notice notice-error" role="alert">{{ t('metrics.loadFailed') }} {{ error }}</p>
    <p v-if="loading && parsed === undefined" role="status">{{ t('app.loading') }}</p>

    <template v-if="parsed">
      <p v-if="parsed.families.length === 0" class="notice" role="status">{{ t('metrics.empty') }}</p>
      <div v-for="family in parsed.families" :key="family.name" class="section panel family">
        <h2 class="mono">{{ family.name }}</h2>
        <p v-if="family.help">{{ family.help }}</p>
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th scope="col">{{ t('metrics.labels') }}</th>
                <th scope="col">{{ t('metrics.value') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="family.samples.length === 0">
                <td colspan="2" class="hint">{{ t('metrics.noValues') }}</td>
              </tr>
              <tr v-for="(sample, index) in family.samples" :key="index">
                <td class="mono">
                  <template v-if="sample.labels.length === 0">{{ t('common.none') }}</template>
                  <span v-for="[name, value] in sample.labels" v-else :key="name" class="label">{{ name }}: {{ value }}</span>
                </td>
                <td class="mono">
                  {{ sample.value }}
                  <TimeStamp v-if="moment(family, sample.value)" :value="moment(family, sample.value) ?? ''" />
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

    </template>
  </section>
</template>

<style scoped>
.family h2 {
  margin: 0;
  font-size: 1rem;
  overflow-wrap: anywhere;
}

.label {
  display: block;
}
</style>
