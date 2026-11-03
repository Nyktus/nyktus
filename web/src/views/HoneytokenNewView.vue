<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import { errorText } from '../api/messages';
import HoneytokenForm from '../components/HoneytokenForm.vue';
import { t } from '../i18n';

const route = useRoute();
const router = useRouter();
// A link from a scenario names it, so that the new honeytoken joins it.
const scenario = typeof route.query.scenario === 'string' ? route.query.scenario : '';
const busy = ref(false);
const error = ref<string | undefined>();

async function create(body: Parameters<typeof api.call<'createHoneytoken'>>[1]['body']): Promise<void> {
  busy.value = true;
  error.value = undefined;
  try {
    const { body: created } = await api.call('createHoneytoken', { body });
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
    <HoneytokenForm :scenario="scenario" :busy="busy" :submit-label="t('honeytokens.create.submit')" @create="create" />
  </section>
</template>

<style scoped>
.narrow {
  max-width: 36rem;
}
</style>
