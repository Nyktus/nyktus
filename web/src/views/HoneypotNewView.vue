<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onBeforeUnmount, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { OperationTypes } from '../api/generated';
import { errorText } from '../api/messages';
import HoneypotForm from '../components/HoneypotForm.vue';
import SecretReveal from '../components/SecretReveal.vue';
import { t } from '../i18n';

type Body = OperationTypes['createHoneypot']['body'];

const route = useRoute();
const router = useRouter();
// A link from a scenario names it, so that the new honeypot joins it.
const scenario = computed(() => (typeof route.query.scenario === 'string' ? route.query.scenario : ''));
const busy = ref(false);
const error = ref<string | undefined>();
const createdId = ref<string | undefined>();
// Set when the page of the honeypot did not open, so that the user is not left with a title and nothing else.
const leaveFailed = ref(false);
// The secret is shown right after the creation. It lives here and nowhere else, and goes when the
// user is done or leaves the page: it is in no store, no address and no history.
const revealed = ref<{ secret: string; config: string } | undefined>();

function discard(): void {
  revealed.value = undefined;
}

// The secret is gone with the click, so the page has nothing left to show: the user lands on the honeypot.
async function finish(): Promise<void> {
  const id = createdId.value;
  discard();
  if (id !== undefined) {
    const failure = await router.replace({ name: 'honeypot', params: { id } }).catch(() => true);
    leaveFailed.value = failure !== undefined;
  }
}

async function create(body: Body): Promise<void> {
  busy.value = true;
  error.value = undefined;
  try {
    const result = (await api.call('createHoneypot', { body })).body;
    createdId.value = result.id;
    revealed.value = { secret: result.secret, config: result.sensor_config };
  } catch (failure) {
    error.value = errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
  } finally {
    busy.value = false;
  }
}

onBeforeUnmount(discard);
</script>

<template>
  <section class="narrow">
    <p><RouterLink :to="{ name: 'honeypots' }">{{ t('honeypots.back') }}</RouterLink></p>
    <div class="page-head"><h1>{{ t('honeypots.create.title') }}</h1></div>
    <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>

    <template v-if="createdId !== undefined">
      <SecretReveal v-if="revealed" :secret="revealed.secret" :config="revealed.config" @done="finish" />
      <p v-else-if="leaveFailed">
        <RouterLink class="button button-primary" :to="{ name: 'honeypot', params: { id: createdId } }">{{ t('honeypots.title') }}</RouterLink>
      </p>
    </template>
    <HoneypotForm v-else :key="scenario" :scenario="scenario" :busy="busy" :submit-label="t('honeypots.create.submit')" @create="create" />
  </section>
</template>

<style scoped>
.narrow {
  max-width: 44rem;
}
</style>
