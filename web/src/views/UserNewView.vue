<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { ref } from 'vue';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { ActivationLink, User } from '../api/generated';
import { errorText } from '../api/messages';
import LinkReveal from '../components/LinkReveal.vue';
import { t } from '../i18n';

const roles = ['admin', 'user', 'viewer'] as const;

const email = ref('');
const displayName = ref('');
const role = ref<User['role']>('viewer');
const busy = ref(false);
const error = ref<string | undefined>();
const created = ref<User | undefined>();
// The link is shown once. It lives here and nowhere else, and goes when the user is
// done or leaves the page, which ends the component and its state.
const once = ref<ActivationLink | undefined>();

function discard(): void {
  once.value = undefined;
}

async function create(): Promise<void> {
  error.value = undefined;
  // A name of spaces passes the required field, and the server would refuse it without saying which field.
  if (displayName.value.trim() === '') {
    error.value = t('field.nameRequired');
    return;
  }
  busy.value = true;
  try {
    const result = (await api.call('createUser', { body: { email: email.value.trim(), display_name: displayName.value.trim(), role: role.value } })).body;
    created.value = result.user;
    once.value = result.activation;
  } catch (failure) {
    error.value = errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
  } finally {
    busy.value = false;
  }
}

</script>

<template>
  <section class="narrow">
    <p><RouterLink :to="{ name: 'users' }">{{ t('users.back') }}</RouterLink></p>
    <div class="page-head"><h1>{{ t('users.create.title') }}</h1></div>
    <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>

    <template v-if="created !== undefined">
      <LinkReveal v-if="once" kind="activation" :url="once.url" :expires-at="once.expires_at" @done="discard" />
      <p>
        <RouterLink class="button button-primary" :to="{ name: 'user', params: { id: created.id } }">{{ t('users.toAccount') }}</RouterLink>
      </p>
    </template>

    <form v-else class="stack" @submit.prevent="create">
      <div class="field">
        <label for="email">{{ t('field.email') }}</label>
        <input id="email" v-model="email" type="email" required maxlength="254" autocomplete="off" spellcheck="false" aria-describedby="email-hint" />
        <span id="email-hint" class="hint">{{ t('users.emailHint') }}</span>
      </div>
      <div class="field">
        <label for="display-name">{{ t('field.displayName') }}</label>
        <input id="display-name" v-model="displayName" type="text" required maxlength="100" autocomplete="off" />
      </div>
      <div class="field">
        <label for="role">{{ t('users.role') }}</label>
        <select id="role" v-model="role" aria-describedby="role-hint">
          <option v-for="option in roles" :key="option" :value="option">{{ t(`role.${option}`) }}</option>
        </select>
        <span id="role-hint" class="hint">{{ t(`role.${role}.hint`) }}</span>
      </div>
      <div class="actions-row">
        <button class="button button-primary" type="submit" :disabled="busy">{{ busy ? t('app.saving') : t('users.create.submit') }}</button>
      </div>
    </form>
  </section>
</template>

<style scoped>
.narrow {
  max-width: 36rem;
}
</style>
