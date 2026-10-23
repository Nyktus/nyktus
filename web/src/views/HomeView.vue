<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { api } from '../api/client';
import { t } from '../i18n';
import { session } from '../session';

const user = computed(() => session.state.session?.user);
const waiting = ref(false);

// The API does not count, so the page asks for one open incident and says that some
// wait, without a number.
onMounted(async () => {
  if (!session.can('incidents:read')) {
    return;
  }
  try {
    waiting.value = (await api.call('listIncidents', { query: { limit: 1, status: 'open' } })).body.incidents.length > 0;
  } catch {
    // The overview works without the hint.
  }
});
</script>

<template>
  <section v-if="user" class="page">
    <h1>{{ t('home.title') }}</h1>
    <p>{{ t('home.welcome', { name: user.display_name }) }}</p>
    <p>{{ t('home.role', { role: t(`role.${user.role}`) }) }}</p>
    <p v-if="waiting" class="notice" role="status">
      {{ t('home.waiting') }}
      <RouterLink :to="{ name: 'incidents' }">{{ t('home.waitingAction') }}</RouterLink>
    </p>
  </section>
</template>

<style scoped>
.page {
  display: grid;
  gap: 0.75rem;
  max-width: 36rem;
}
</style>
