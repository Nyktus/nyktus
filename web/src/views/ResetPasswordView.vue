<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { ref } from 'vue';
import { api } from '../api/client';
import AuthCard from '../components/AuthCard.vue';
import NewPasswordFields from '../components/NewPasswordFields.vue';
import { t } from '../i18n';
import { useLinkForm } from '../session/linkForm';
import { checkNewPassword, passwordLength } from '../session/passwordRules';

const password = ref('');
const repeat = ref('');

const { state, busy, error, submit } = useLinkForm(
  async (token) => {
    await api.call('resetPassword', { body: { token, password: password.value } });
  },
  () => {
    password.value = '';
    repeat.value = '';
  },
);

function send(): Promise<void> {
  const problem = checkNewPassword(password.value, repeat.value);
  return submit(problem === undefined ? undefined : t(`password.${problem}`, passwordLength));
}
</script>

<template>
  <AuthCard :title="t('reset.title')">
    <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>
    <template v-if="state === 'form'">
      <p>{{ t('reset.intro') }}</p>
      <form class="stack" @submit.prevent="send">
        <NewPasswordFields v-model:password="password" v-model:repeat="repeat" />
        <button class="button button-primary" type="submit" :disabled="busy">
          {{ busy ? t('app.saving') : t('reset.submit') }}
        </button>
      </form>
    </template>
    <template v-else>
      <p class="notice" role="status">{{ state === 'done' ? t('reset.done') : t('link.invalid') }}</p>
      <RouterLink class="button button-primary" :to="{ name: 'sign-in' }">{{ t('link.toSignIn') }}</RouterLink>
    </template>
  </AuthCard>
</template>

<style scoped>
.stack {
  display: grid;
  gap: 1rem;
}
</style>
