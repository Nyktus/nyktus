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

const email = ref('');
const displayName = ref('');
const password = ref('');
const repeat = ref('');

const { state, busy, error, submit } = useLinkForm(
  async (token) => {
    await api.call('createFirstAdministrator', {
      body: { token, email: email.value, display_name: displayName.value.trim(), password: password.value },
    });
  },
  () => {
    email.value = '';
    displayName.value = '';
    password.value = '';
    repeat.value = '';
  },
);

function send(): Promise<void> {
  // A name of spaces passes the required field, and the server would refuse it without saying which field.
  if (displayName.value.trim() === '') {
    return submit(t('field.nameRequired'));
  }
  const problem = checkNewPassword(password.value, repeat.value);
  return submit(problem === undefined ? undefined : t(`password.${problem}`, passwordLength));
}
</script>

<template>
  <AuthCard :title="t('setup.title')">
    <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>
    <template v-if="state === 'form'">
      <p>{{ t('setup.intro') }}</p>
      <form class="stack" @submit.prevent="send">
        <div class="field">
          <label for="email">{{ t('field.email') }}</label>
          <input id="email" v-model="email" type="email" name="email" autocomplete="username" required maxlength="254" />
        </div>
        <div class="field">
          <label for="display-name">{{ t('field.displayName') }}</label>
          <input
            id="display-name"
            v-model="displayName"
            type="text"
            name="display-name"
            autocomplete="name"
            required
            maxlength="100"
          />
        </div>
        <NewPasswordFields v-model:password="password" v-model:repeat="repeat" />
        <button class="button button-primary" type="submit" :disabled="busy">
          {{ busy ? t('app.saving') : t('setup.submit') }}
        </button>
      </form>
    </template>
    <template v-else>
      <p class="notice" role="status">{{ state === 'done' ? t('setup.done') : t('setup.invalid') }}</p>
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
