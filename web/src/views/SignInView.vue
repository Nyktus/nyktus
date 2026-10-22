<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { nextTick, onMounted, ref, useTemplateRef } from 'vue';
import { useRouter } from 'vue-router';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import { operations, type OperationTypes } from '../api/generated';
import { errorText } from '../api/messages';
import { t } from '../i18n';
import { leaveSignIn } from '../router';
import { session } from '../session';
import markUrl from '../assets/mark.svg';

type Options = OperationTypes['getSignInOptions']['responses'][200];

const router = useRouter();

const options = ref<Options | undefined>();
const optionsFailed = ref(false);
const step = ref<'password' | 'second-factor'>('password');
const recovery = ref(false);
const busy = ref(false);
const error = ref<string | undefined>();

// These hold what the user types only until the request is sent.
const email = ref('');
const password = ref('');
const code = ref('');

const emailInput = useTemplateRef<HTMLInputElement>('email-input');
const codeInput = useTemplateRef<HTMLInputElement>('code-input');

async function loadOptions(): Promise<void> {
  optionsFailed.value = false;
  try {
    options.value = (await api.call('getSignInOptions', {})).body;
  } catch {
    optionsFailed.value = true;
  }
}

onMounted(async () => {
  // The provider sends the browser back with a fragment when its sign-in failed.
  // The fragment says no more than that, and does not stay in the history.
  if (globalThis.location.hash === '#error=oidc') {
    error.value = t('error.sso');
    globalThis.history.replaceState(globalThis.history.state, '', globalThis.location.pathname + globalThis.location.search);
  }
  await loadOptions();
  await nextTick();
  emailInput.value?.focus();
});

function show(failure: unknown): void {
  error.value = errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
}

async function submitPassword(): Promise<void> {
  if (busy.value) {
    return;
  }
  busy.value = true;
  error.value = undefined;
  const typed = password.value;
  password.value = '';
  try {
    const outcome = await session.signIn(email.value, typed);
    if (outcome.next === 'done') {
      email.value = '';
      await leaveSignIn(router);
      return;
    }
    step.value = 'second-factor';
    recovery.value = false;
    await nextTick();
    codeInput.value?.focus();
  } catch (failure) {
    show(failure);
  } finally {
    busy.value = false;
  }
}

async function submitSecondFactor(): Promise<void> {
  if (busy.value) {
    return;
  }
  busy.value = true;
  error.value = undefined;
  const typed = code.value.trim();
  try {
    await session.completeSecondFactor(recovery.value ? { recovery_code: typed } : { code: typed });
    email.value = '';
    code.value = '';
    await leaveSignIn(router);
  } catch (failure) {
    show(failure);
    // The challenge is gone when it expired or the account is locked.
    if (failure instanceof ApiError && (failure.kind === 'invalid_challenge' || failure.kind === 'account_locked')) {
      startAgain(false);
    }
  } finally {
    busy.value = false;
  }
}

function startAgain(clearError = true): void {
  step.value = 'password';
  code.value = '';
  password.value = '';
  if (clearError) {
    error.value = undefined;
  }
  void nextTick(() => emailInput.value?.focus());
}

function switchFactor(): void {
  recovery.value = !recovery.value;
  code.value = '';
  error.value = undefined;
  void nextTick(() => codeInput.value?.focus());
}
</script>

<template>
  <main class="stage">
    <div class="card panel">
      <div class="brand">
        <img :src="markUrl" alt="" width="36" height="36" />
        <span>Nyktus</span>
      </div>
      <h1>{{ step === 'password' ? t('signIn.title') : t('secondFactor.title') }}</h1>

      <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>

      <template v-if="step === 'password'">
        <div v-if="optionsFailed" class="stack">
          <p class="notice" role="status">{{ t('signIn.loadFailed') }}</p>
          <button class="button button-ghost" type="button" @click="loadOptions">{{ t('signIn.retry') }}</button>
        </div>
        <p v-else-if="options === undefined" role="status">{{ t('app.loading') }}</p>
        <template v-else>
          <form v-if="options.password" class="stack" @submit.prevent="submitPassword">
            <div class="field">
              <label for="email">{{ t('signIn.email') }}</label>
              <input
                id="email"
                ref="email-input"
                v-model="email"
                type="email"
                name="email"
                autocomplete="username"
                required
                maxlength="254"
              />
            </div>
            <div class="field">
              <label for="password">{{ t('signIn.password') }}</label>
              <input
                id="password"
                v-model="password"
                type="password"
                name="password"
                autocomplete="current-password"
                required
                maxlength="1024"
              />
            </div>
            <button class="button button-primary" type="submit" :disabled="busy">
              {{ busy ? t('signIn.submitting') : t('signIn.submit') }}
            </button>
          </form>

          <p v-if="options.password && options.oidc !== 'off'" class="or" aria-hidden="true">{{ t('signIn.or') }}</p>

          <a v-if="options.oidc === 'available'" class="button button-ghost" :href="operations.beginOIDCSignIn.path">
            {{ t('signIn.sso') }}
          </a>
          <template v-else-if="options.oidc === 'unavailable'">
            <button class="button button-ghost" type="button" aria-disabled="true" aria-describedby="sso-hint">
              {{ t('signIn.sso') }}
            </button>
            <p id="sso-hint" class="hint">{{ t('signIn.ssoUnavailable') }}</p>
          </template>

          <p v-if="!options.password && options.oidc === 'off'" class="notice">{{ t('signIn.noMethod') }}</p>
        </template>
      </template>

      <form v-else class="stack" @submit.prevent="submitSecondFactor">
        <p>{{ recovery ? t('secondFactor.recoveryIntro') : t('secondFactor.intro') }}</p>
        <div class="field">
          <label for="code">{{ recovery ? t('secondFactor.recoveryCode') : t('secondFactor.code') }}</label>
          <input
            id="code"
            ref="code-input"
            v-model="code"
            type="text"
            name="code"
            :inputmode="recovery ? 'text' : 'numeric'"
            autocomplete="one-time-code"
            :pattern="recovery ? undefined : '[0-9]{6}'"
            :maxlength="recovery ? 64 : 6"
            required
            spellcheck="false"
            class="mono"
          />
        </div>
        <button class="button button-primary" type="submit" :disabled="busy">{{ t('secondFactor.submit') }}</button>
        <button class="link" type="button" @click="switchFactor">
          {{ recovery ? t('secondFactor.useCode') : t('secondFactor.useRecovery') }}
        </button>
        <button class="link" type="button" @click="startAgain()">{{ t('secondFactor.back') }}</button>
      </form>
    </div>
  </main>
</template>

<style scoped>
.stage {
  display: grid;
  min-height: 100vh;
  padding: var(--gutter);
  place-items: center;
}

.card {
  display: grid;
  gap: 1.1rem;
  width: min(100%, 26rem);
  padding: 2rem;
}

.brand {
  display: flex;
  align-items: center;
  gap: 0.65rem;
  font-size: 1.3rem;
  font-weight: 800;
  letter-spacing: -0.03em;
}

.stack {
  display: grid;
  gap: 1rem;
}

.or {
  color: var(--slate);
  text-align: center;
}

.hint {
  color: var(--slate);
  font-size: 0.8125rem;
}

.link {
  padding: 0.25rem 0;
  border: 0;
  background: none;
  color: var(--forest);
  font: inherit;
  text-align: left;
  text-decoration: underline;
  text-underline-offset: 0.15em;
  cursor: pointer;
}

.link:hover {
  color: var(--forest-deep);
}
</style>
