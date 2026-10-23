<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, ref } from 'vue';
import { api } from '../api/client';
import { keyScopes, type KeyScope } from '../api/generated';
import { errorText } from '../api/messages';
import ConfirmWithPassword from '../components/ConfirmWithPassword.vue';
import KeyReveal from '../components/KeyReveal.vue';
import { t } from '../i18n';
import { earliestExpiry, expiryAllowed, expiryTime, latestExpiry } from '../keyExpiry';
import { dependentsOf, deselect, requirementsOf, select } from '../keyScopes';

const name = ref('');
const expires = ref('');
const scopes = ref<KeyScope[]>([]);
const problem = ref<string | undefined>();
const error = ref<string | undefined>();
const confirming = ref(false);
const done = ref(false);
// The key is shown once. It lives here and nowhere else, and goes when the user is
// done or leaves the page, which ends the component and its state.
const once = ref<string | undefined>();

const earliest = computed(() => earliestExpiry(new Date()));
const latest = computed(() => latestExpiry(new Date()));

function toggle(scope: KeyScope, on: boolean): void {
  scopes.value = on ? select(scopes.value, scope) : deselect(scopes.value, scope);
}

function neededBy(scope: KeyScope): string {
  return dependentsOf(scopes.value, scope).join(', ');
}

function ask(): void {
  error.value = undefined;
  problem.value = undefined;
  if (name.value.trim() === '') {
    problem.value = t('apiKeys.nameRequired');
  } else if (scopes.value.length === 0) {
    problem.value = t('apiKeys.scopesRequired');
  } else if (!expiryAllowed(expires.value, new Date())) {
    problem.value = t('apiKeys.expiryInvalid', { from: earliest.value, to: latest.value });
  } else {
    confirming.value = true;
  }
}

/** The password is added here and goes nowhere else: it is not kept with the form. */
async function create(password: string | undefined): Promise<void> {
  const { body } = await api.call('createAPIKey', {
    body: { name: name.value.trim(), scopes: scopes.value, expires_at: expiryTime(expires.value), password },
  });
  once.value = body.key;
}

function created(): void {
  confirming.value = false;
  done.value = true;
}

function refused(failure: Parameters<typeof errorText>[0]): void {
  confirming.value = false;
  error.value = errorText(failure);
}
</script>

<template>
  <section class="narrow">
    <p><RouterLink :to="{ name: 'api-keys' }">{{ t('apiKeys.back') }}</RouterLink></p>
    <div class="page-head"><h1>{{ t('apiKeys.create.title') }}</h1></div>

    <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>

    <template v-if="done">
      <KeyReveal v-if="once" :secret="once" @done="once = undefined" />
      <p>
        <RouterLink class="button button-primary" :to="{ name: 'api-keys' }">{{ t('apiKeys.title') }}</RouterLink>
      </p>
    </template>

    <form v-else class="stack" @submit.prevent="ask">
      <div class="field">
        <label for="key-name">{{ t('field.name') }}</label>
        <input id="key-name" v-model="name" type="text" required maxlength="64" autocomplete="off" aria-describedby="key-name-hint" />
        <span id="key-name-hint" class="hint">{{ t('apiKeys.nameHint') }}</span>
      </div>

      <div class="field">
        <label for="key-expires">{{ t('apiKeys.expires') }}</label>
        <input id="key-expires" v-model="expires" type="date" required :min="earliest" :max="latest" aria-describedby="key-expires-hint" />
        <span id="key-expires-hint" class="hint">{{ t('apiKeys.expiresHint') }}</span>
      </div>

      <fieldset class="scopes">
        <legend>{{ t('apiKeys.scopes') }}</legend>
        <p class="hint">{{ t('apiKeys.scopesHint') }}</p>
        <div v-for="(scope, index) in keyScopes" :key="scope" class="field">
          <label class="check" :for="`scope-${index}`">
            <input
              :id="`scope-${index}`"
              type="checkbox"
              :checked="scopes.includes(scope)"
              :disabled="scopes.includes(scope) && dependentsOf(scopes, scope).length > 0"
              @change="toggle(scope, ($event.target as HTMLInputElement).checked)"
            />
            <span>
              <code class="mono">{{ scope }}</code>
              {{ t(`scope.${scope}`) }}
            </span>
          </label>
          <span v-if="scopes.includes(scope) && dependentsOf(scopes, scope).length > 0" class="hint">{{ t('apiKeys.neededBy', { scopes: neededBy(scope) }) }}</span>
          <span v-else-if="requirementsOf(scope).length > 0" class="hint">{{ t('apiKeys.requires', { scopes: requirementsOf(scope).join(', ') }) }}</span>
        </div>
      </fieldset>

      <p v-if="problem" class="notice notice-error" role="alert">{{ problem }}</p>

      <div class="actions-row">
        <button class="button button-primary" type="submit">{{ t('apiKeys.create.submit') }}</button>
      </div>
    </form>

    <ConfirmWithPassword
      :open="confirming"
      :title="t('apiKeys.create.confirmTitle')"
      :confirm="t('apiKeys.create.submit')"
      :action="create"
      @done="created"
      @cancel="confirming = false"
      @failed="refused"
    >
      {{ t('apiKeys.create.confirmBody') }}
    </ConfirmWithPassword>
  </section>
</template>

<style scoped>
.narrow {
  max-width: 44rem;
}

.scopes {
  display: grid;
  gap: 0.6rem;
  margin: 0;
  padding: 0;
  border: 0;
}

.scopes legend {
  padding: 0;
  font-weight: 600;
}
</style>
