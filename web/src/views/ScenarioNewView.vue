<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { OperationTypes } from '../api/generated';
import { errorText } from '../api/messages';
import ScenarioForm from '../components/ScenarioForm.vue';
import { t } from '../i18n';

const router = useRouter();
const busy = ref(false);
const error = ref<string | undefined>();

async function create(body: OperationTypes['createScenario']['body']): Promise<void> {
  busy.value = true;
  error.value = undefined;
  try {
    const { body: created } = await api.call('createScenario', { body });
    await router.replace({ name: 'scenario', params: { id: created.id } });
  } catch (failure) {
    error.value = errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <section class="narrow">
    <p><RouterLink :to="{ name: 'scenarios' }">{{ t('scenarios.back') }}</RouterLink></p>
    <div class="page-head"><h1>{{ t('scenarios.create.title') }}</h1></div>
    <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>
    <ScenarioForm :busy="busy" :submit-label="t('scenarios.create.submit')" @create="create" />
  </section>
</template>

<style scoped>
.narrow {
  max-width: 36rem;
}
</style>
