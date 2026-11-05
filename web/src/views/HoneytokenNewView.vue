<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import { errorText } from '../api/messages';
import HoneytokenForm from '../components/HoneytokenForm.vue';
import { t } from '../i18n';
import { readHoneytokenPrefill } from '../slotPrefill';

const route = useRoute();
const router = useRouter();
// A link from a scenario names it, so that the new honeytoken joins it.
const scenario = computed(() => (typeof route.query.scenario === 'string' ? route.query.scenario : ''));
// A link from a slot of a scenario also names what the slot asks for. Only values the form offers are taken over.
const prefill = computed(() => readHoneytokenPrefill(route.query));
const busy = ref(false);
const error = ref<string | undefined>();

async function create(body: Parameters<typeof api.call<'createHoneytoken'>>[1]['body']): Promise<void> {
  busy.value = true;
  error.value = undefined;
  try {
    const { body: created } = await api.call('createHoneytoken', { body });
    // Whoever came from a scenario goes back to it, where the value to place stands in the table of its honeytokens.
    if (scenario.value !== '' && created.scenario_id === scenario.value) {
      await router.replace({ name: 'scenario', params: { id: scenario.value } });
      return;
    }
    await router.replace({ name: 'honeytoken', params: { id: created.id }, query: { created: '1' } });
  } catch (failure) {
    error.value = errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <section class="narrow">
    <p><RouterLink :to="{ name: 'honeytokens' }">{{ t('honeytokens.back') }}</RouterLink></p>
    <div class="page-head"><h1>{{ t('honeytokens.create.title') }}</h1></div>
    <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>
    <HoneytokenForm :key="route.fullPath" :scenario="scenario" :prefill="prefill" :busy="busy" :submit-label="t('honeytokens.create.submit')" @create="create" />
  </section>
</template>

<style scoped>
.narrow {
  max-width: 36rem;
}
</style>
