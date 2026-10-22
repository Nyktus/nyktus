<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { onBeforeUnmount, ref } from 'vue';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { OperationTypes } from '../api/generated';
import { errorText } from '../api/messages';
import HoneypotForm from '../components/HoneypotForm.vue';
import SecretReveal from '../components/SecretReveal.vue';
import { t } from '../i18n';

type Body = OperationTypes['createHoneypot']['body'];

const busy = ref(false);
const error = ref<string | undefined>();
const createdId = ref<string | undefined>();
// The secret is shown once. It lives here and nowhere else, and goes when the user
// is done or leaves the page: it is in no store, no address and no history.
const once = ref<{ secret: string; config: string } | undefined>();

function discard(): void {
  once.value = undefined;
}

async function create(body: Body): Promise<void> {
  busy.value = true;
  error.value = undefined;
  try {
    const result = (await api.call('createHoneypot', { body })).body;
    createdId.value = result.id;
    once.value = { secret: result.secret, config: result.sensor_config };
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
      <SecretReveal v-if="once" :secret="once.secret" :config="once.config" @done="discard" />
      <p>
        <RouterLink class="button button-primary" :to="{ name: 'honeypot', params: { id: createdId } }">{{ t('honeypots.title') }}</RouterLink>
      </p>
    </template>
    <HoneypotForm v-else :busy="busy" :submit-label="t('honeypots.create.submit')" @create="create" />
  </section>
</template>

<style scoped>
.narrow {
  max-width: 44rem;
}
</style>
