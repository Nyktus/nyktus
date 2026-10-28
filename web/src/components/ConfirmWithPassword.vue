<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, ref, useId, watch } from 'vue';
import { useRouter } from 'vue-router';
import { ApiError } from '../api/errors';
import { errorText } from '../api/messages';
import { t } from '../i18n';
import { session } from '../session';
import { reauthenticationAddress, takeReauthenticationFailure } from '../session/reauthentication';
import ConfirmDialog from './ConfirmDialog.vue';

// A change that decides where alerts go, or who may reach the console, is confirmed
// by the person who makes it: a local account types its password, an account of the
// identity provider signs in there again. The password is held in this component and
// only while the request that carries it is on its way. A page that asks for a code as
// well puts the field in the slot and holds the code the same way.
const props = defineProps<{
  open: boolean;
  title: string;
  confirm: string;
  /** Makes the request. It gets the password of a local account, and nothing for an account of the identity provider. */
  action: (password: string | undefined) => Promise<void>;
}>();

const emit = defineEmits<{
  done: [];
  cancel: [];
  /** The request failed for a reason that the user cannot mend here; the page tells them. */
  failed: [error: ApiError];
}>();

const router = useRouter();
const id = useId();

const password = ref('');
const busy = ref(false);
const message = ref<string | undefined>();
const needsReauthentication = ref(false);
const reauthenticationFailed = ref(false);

const local = computed(() => session.state.session?.user.sign_in_method !== 'oidc');
const account = computed(() => session.state.session?.user.email ?? '');
const label = computed(() => (needsReauthentication.value ? t('confirm.reauthenticate') : props.confirm));

onMounted(() => {
  reauthenticationFailed.value = takeReauthenticationFailure(globalThis.location, globalThis.history);
});

// A dialog that is closed keeps neither a password nor an old error, and one that opens
// again is a new attempt: the note about the last one has done its job.
watch(
  () => props.open,
  (open) => {
    password.value = '';
    message.value = undefined;
    needsReauthentication.value = false;
    if (open) {
      reauthenticationFailed.value = false;
    }
  },
);

async function run(): Promise<void> {
  if (busy.value) {
    return;
  }
  if (needsReauthentication.value) {
    // The browser goes to the identity provider and comes back to this page.
    globalThis.location.assign(reauthenticationAddress(router.currentRoute.value.fullPath));
    return;
  }
  if (local.value && password.value === '') {
    message.value = t('confirm.passwordRequired');
    return;
  }
  busy.value = true;
  message.value = undefined;
  try {
    await props.action(local.value ? password.value : undefined);
    emit('done');
  } catch (failure) {
    const error = failure instanceof ApiError ? failure : new ApiError('server', 0);
    if (error.kind === 'wrong_password') {
      message.value = t('confirm.wrongPassword');
    } else if (error.kind === 'wrong_code') {
      message.value = t('confirm.wrongCode');
    } else if (error.kind === 'account_locked') {
      message.value = errorText(error);
    } else if (error.kind === 'reauthentication_required') {
      needsReauthentication.value = true;
      message.value = t('confirm.reauthenticateHint');
    } else {
      emit('failed', error);
    }
  } finally {
    // Whatever happened, the password does not outlive the request.
    password.value = '';
    busy.value = false;
  }
}
</script>

<template>
  <p v-if="reauthenticationFailed" class="notice notice-error" role="alert">{{ t('confirm.reauthenticationFailed') }}</p>
  <ConfirmDialog :open="open" :title="title" :confirm="label" :busy="busy" neutral @confirm="run" @cancel="emit('cancel')">
    <div class="stack">
      <slot />
      <form v-if="local" class="field" @submit.prevent="run">
        <!-- A password manager files a password under an account, so the form names it; the field is not for the user. -->
        <input class="visually-hidden" type="text" name="username" autocomplete="username" :value="account" readonly tabindex="-1" aria-hidden="true" />
        <!-- With two text fields the browser no longer submits on Enter by itself, so the form needs a submit button. -->
        <button type="submit" hidden tabindex="-1" aria-hidden="true"></button>
        <label :for="`${id}-password`">{{ t('confirm.password') }}</label>
        <input :id="`${id}-password`" v-model="password" type="password" name="password" autocomplete="current-password" required />
      </form>
      <p v-if="message" class="notice notice-error" role="alert">{{ message }}</p>
    </div>
  </ConfirmDialog>
</template>
