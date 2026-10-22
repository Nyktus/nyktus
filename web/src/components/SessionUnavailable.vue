<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { t } from '../i18n';
import { session } from '../session';
import markUrl from '../assets/mark.svg';

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
  <main class="stage">
    <div class="card panel">
      <div class="brand">
        <img :src="markUrl" alt="" width="36" height="36" />
        <span>Nyktus</span>
      </div>
      <h1>{{ t('session.unavailable.title') }}</h1>
      <p class="notice" role="alert">{{ t('session.unavailable.body') }}</p>
      <button class="button button-primary" type="button" :disabled="busy" @click="retry">{{ t('session.retry') }}</button>
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
</style>
