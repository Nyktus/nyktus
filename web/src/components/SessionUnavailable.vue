<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { t } from '../i18n';
import { session } from '../session';
import AuthCard from './AuthCard.vue';

// The server did not answer when the page asked for the session. The user is not
// signed out for that: the session may be valid, so the page asks again and shows
// the page the user was going to, or the sign-in if the server then says there is none.
const router = useRouter();
const busy = ref(false);

async function retry(): Promise<void> {
  busy.value = true;
  try {
    await session.ensureLoaded();
    const current = router.currentRoute.value;
    await router.replace({ path: current.path, query: current.query, hash: current.hash, force: true });
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <AuthCard :title="t('session.unavailable.title')">
    <p class="notice" role="alert">{{ t('session.unavailable.body') }}</p>
    <button class="button button-primary" type="button" :disabled="busy" @click="retry">{{ t('session.retry') }}</button>
  </AuthCard>
</template>
