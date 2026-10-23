<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, ref, useId, watch } from 'vue';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { OperationTypes, TOTPSetup, User } from '../api/generated';
import { errorText } from '../api/messages';
import ConfirmWithPassword from '../components/ConfirmWithPassword.vue';
import NewPasswordFields from '../components/NewPasswordFields.vue';
import QrCode from '../components/QrCode.vue';
import RecoveryCodes from '../components/RecoveryCodes.vue';
import TimeStamp from '../components/TimeStamp.vue';
import { t } from '../i18n';
import { checkNewPassword, passwordLength } from '../session/passwordRules';

type Confirmation = OperationTypes['removeTOTP']['body'];

const replaceCodeId = useId();
const removeCodeId = useId();

const user = ref<User | undefined>();
const loading = ref(true);
const error = ref<string | undefined>();
const totpEnabled = ref(false);

const local = computed(() => user.value?.sign_in_method === 'password');

function show(failure: unknown): string {
  return errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
}

onMounted(async () => {
  try {
    // The session of the page is a copy from when it signed in; the factor may have changed since.
    user.value = (await api.call('getSession', {})).body.user;
    totpEnabled.value = user.value.totp_enabled;
  } catch (failure) {
    error.value = show(failure);
  } finally {
    loading.value = false;
  }
});

// The password. The form is the confirmation: the user gives the current one, and every
// password that was typed is gone once the request has been answered.
const currentPassword = ref('');
const newPassword = ref('');
const repeatPassword = ref('');
const passwordBusy = ref(false);
const passwordError = ref<string | undefined>();
const passwordChanged = ref(false);

async function changePassword(): Promise<void> {
  passwordError.value = undefined;
  passwordChanged.value = false;
  const problem = checkNewPassword(newPassword.value, repeatPassword.value);
  if (problem !== undefined) {
    passwordError.value = t(`password.${problem}`, passwordLength);
    return;
  }
  passwordBusy.value = true;
  try {
    await api.call('changePassword', { body: { current_password: currentPassword.value, new_password: newPassword.value } });
    passwordChanged.value = true;
  } catch (failure) {
    passwordError.value = failure instanceof ApiError && failure.kind === 'wrong_password' ? t('account.password.wrong') : show(failure);
  } finally {
    currentPassword.value = '';
    newPassword.value = '';
    repeatPassword.value = '';
    passwordBusy.value = false;
  }
}

// The second factor. The key and the recovery codes are shown once, on this page, and
// are in no store, no address and no history.
const setup = ref<TOTPSetup | undefined>();
const setupExpired = ref(false);
const setupCode = ref('');
const setupError = ref<string | undefined>();
const setupBusy = ref(false);
const codes = ref<string[] | undefined>();
const beginning = ref(false);
const replacing = ref(false);
const removing = ref(false);
const dialogCode = ref('');
const factorError = ref<string | undefined>();

const grouped = computed(() => (setup.value?.secret.match(/.{1,4}/g) ?? []).join(' '));

// What the user typed may be spaced or hyphenated, as an app shows it: six digits are a code, anything else a recovery code.
function confirmation(password: string): Confirmation {
  const typed = dialogCode.value.trim();
  if (typed === '') {
    // Nothing to send: the server would only refuse it, and a refusal counts against the account.
    throw new ApiError('wrong_code', 0);
  }
  const digits = typed.replace(/[\s-]/g, '');
  return /^\d{6}$/.test(digits) ? { password, code: digits } : { password, recovery_code: typed };
}

watch([replacing, removing], ([a, b]) => {
  if (!a && !b) {
    dialogCode.value = '';
  }
});

async function begin(password: string | undefined): Promise<void> {
  factorError.value = undefined;
  const { body } = await api.call('beginTOTPSetup', { body: { password: password ?? '' } });
  setup.value = body;
  setupExpired.value = false;
  setupCode.value = '';
  setupError.value = undefined;
}

async function confirmSetup(): Promise<void> {
  const current = setup.value;
  setupError.value = undefined;
  if (current === undefined) {
    return;
  }
  const digits = setupCode.value.replace(/[\s-]/g, '');
  if (!/^\d{6}$/.test(digits)) {
    setupError.value = t('account.setup.codeInvalid');
    return;
  }
  // The server knows when the setup ends: a clock that runs ahead of it must not end it early.
  factorError.value = undefined;
  setupBusy.value = true;
  try {
    codes.value = (await api.call('confirmTOTP', { body: { code: digits } })).body.recovery_codes;
    setup.value = undefined;
    totpEnabled.value = true;
  } catch (failure) {
    if (failure instanceof ApiError && failure.kind === 'wrong_code') {
      setupError.value = t('account.setup.codeWrong');
    } else if (failure instanceof ApiError && failure.kind === 'no_totp_setup') {
      expire();
    } else {
      setupError.value = show(failure);
    }
  } finally {
    setupCode.value = '';
    setupBusy.value = false;
  }
}

function expire(): void {
  setup.value = undefined;
  setupExpired.value = true;
}

/** Asks for the password and the code in one dialog, and clears the code whatever the answer. */
async function replace(password: string | undefined): Promise<void> {
  factorError.value = undefined;
  try {
    codes.value = (await api.call('replaceRecoveryCodes', { body: confirmation(password ?? '') })).body.recovery_codes;
  } finally {
    dialogCode.value = '';
  }
}

async function remove(password: string | undefined): Promise<void> {
  factorError.value = undefined;
  try {
    await api.call('removeTOTP', { body: confirmation(password ?? '') });
    totpEnabled.value = false;
    // The codes that are shown belong to the factor that is gone.
    codes.value = undefined;
  } finally {
    dialogCode.value = '';
  }
}

function refused(failure: ApiError): void {
  // The server says what the factor is: the page that showed another one follows it.
  if (failure.kind === 'totp_enabled') {
    totpEnabled.value = true;
  } else if (failure.kind === 'totp_not_enabled') {
    totpEnabled.value = false;
    codes.value = undefined;
  }
  beginning.value = false;
  replacing.value = false;
  removing.value = false;
  factorError.value = errorText(failure);
}
</script>

<template>
  <section class="narrow">
    <div class="page-head">
      <div>
        <h1>{{ t('account.title') }}</h1>
        <p v-if="user" class="lede"><bdi>{{ user.display_name }}</bdi>, <bdi>{{ user.email }}</bdi></p>
      </div>
    </div>

    <p v-if="loading" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="error" class="notice notice-error" role="alert">{{ error }}</p>

    <template v-else-if="user">
      <p v-if="!local" class="notice" role="status">{{ t('account.provider') }}</p>

      <template v-else>
        <div class="section panel">
          <h2>{{ t('account.password.title') }}</h2>
          <p class="hint">{{ t('account.password.hint') }}</p>
          <p v-if="passwordChanged" class="notice notice-ok" role="status">{{ t('account.password.done') }}</p>
          <p v-if="passwordError" class="notice notice-error" role="alert">{{ passwordError }}</p>
          <form class="stack" @submit.prevent="changePassword">
            <div class="field">
              <label for="current-password">{{ t('account.password.current') }}</label>
              <input id="current-password" v-model="currentPassword" type="password" name="current-password" autocomplete="current-password" required />
            </div>
            <NewPasswordFields v-model:password="newPassword" v-model:repeat="repeatPassword" />
            <div class="actions-row">
              <button class="button button-primary" type="submit" :disabled="passwordBusy">{{ passwordBusy ? t('app.saving') : t('account.password.submit') }}</button>
            </div>
          </form>
        </div>

        <RecoveryCodes v-if="codes" :codes="codes" @done="codes = undefined" />

        <div class="section panel">
          <h2>{{ t('account.factor.title') }}</h2>
          <p v-if="factorError" class="notice notice-error" role="alert">{{ factorError }}</p>

          <template v-if="totpEnabled">
            <p>{{ t('account.factor.on') }}</p>
            <div class="stack">
              <div>
                <p class="hint">{{ t('account.codes.replaceHint') }}</p>
                <button class="button button-ghost" type="button" @click="replacing = true">{{ t('account.codes.replace') }}</button>
              </div>
              <div>
                <p class="hint">{{ t('account.factor.removeHint') }}</p>
                <button class="button button-ghost" type="button" @click="removing = true">{{ t('account.factor.remove') }}</button>
              </div>
            </div>
          </template>

          <template v-else-if="setup">
            <p>{{ t('account.setup.scan') }}</p>
            <div class="setup">
              <QrCode :text="setup.uri" :label="t('account.setup.qr')" />
              <dl class="definition">
                <dt>{{ t('account.setup.key') }}</dt>
                <dd class="mono key">{{ grouped }}</dd>
                <dt>{{ t('account.setup.until') }}</dt>
                <dd><TimeStamp :value="setup.expires_at" /></dd>
              </dl>
            </div>
            <form class="stack" @submit.prevent="confirmSetup">
              <div class="field">
                <label for="setup-code">{{ t('account.setup.code') }}</label>
                <input id="setup-code" v-model="setupCode" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="16" required />
              </div>
              <p v-if="setupError" class="notice notice-error" role="alert">{{ setupError }}</p>
              <div class="actions-row">
                <button class="button button-primary" type="submit" :disabled="setupBusy">{{ t('account.setup.confirm') }}</button>
              </div>
            </form>
          </template>

          <template v-else>
            <p v-if="setupExpired" class="notice notice-error" role="alert">{{ t('account.setup.expired') }}</p>
            <p>{{ t('account.factor.off') }}</p>
            <div class="actions-row">
              <button class="button button-primary" type="button" @click="beginning = true">{{ setupExpired ? t('account.setup.restart') : t('account.factor.setup') }}</button>
            </div>
          </template>
        </div>

        <ConfirmWithPassword
          :open="beginning"
          :title="t('account.setup.title')"
          :confirm="t('account.factor.setup')"
          :action="begin"
          @done="beginning = false"
          @cancel="beginning = false"
          @failed="refused"
        >
          {{ t('account.setup.body') }}
        </ConfirmWithPassword>

        <ConfirmWithPassword
          :open="replacing"
          :title="t('account.codes.replaceTitle')"
          :confirm="t('account.codes.replace')"
          :action="replace"
          @done="replacing = false"
          @cancel="replacing = false"
          @failed="refused"
        >
          <div class="field">
            <label :for="replaceCodeId">{{ t('account.confirm.code') }}</label>
            <input :id="replaceCodeId" v-model="dialogCode" type="text" autocomplete="one-time-code" spellcheck="false" required />
          </div>
        </ConfirmWithPassword>

        <ConfirmWithPassword
          :open="removing"
          :title="t('account.factor.removeTitle')"
          :confirm="t('account.factor.remove')"
          :action="remove"
          @done="removing = false"
          @cancel="removing = false"
          @failed="refused"
        >
          <p>{{ t('account.factor.removeBody') }}</p>
          <div class="field">
            <label :for="removeCodeId">{{ t('account.confirm.code') }}</label>
            <input :id="removeCodeId" v-model="dialogCode" type="text" autocomplete="one-time-code" spellcheck="false" required />
          </div>
        </ConfirmWithPassword>
      </template>
    </template>
  </section>
</template>

<style scoped>
.narrow {
  max-width: 44rem;
}

.setup {
  display: flex;
  flex-wrap: wrap;
  gap: 1.5rem;
  align-items: flex-start;
}

.key {
  letter-spacing: 0.05em;
  overflow-wrap: anywhere;
}
</style>
