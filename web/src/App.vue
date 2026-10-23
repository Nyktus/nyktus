<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { watchEffect } from 'vue';
import { useRoute } from 'vue-router';
import AppShell from './components/AppShell.vue';
import SessionUnavailable from './components/SessionUnavailable.vue';
import { t } from './i18n';
import { session } from './session';

const route = useRoute();

watchEffect(() => {
  if (route.meta.title !== undefined) {
    document.title = `${t(route.meta.title)} - Nyktus`;
  }
});
</script>

<template>
  <!-- Nothing is drawn until the router has arrived at a page: it asks the server for the session first, and the frame must not flash up for a user who is not signed in. -->
  <template v-if="route.matched.length > 0">
    <RouterView v-if="route.meta.public" />
    <SessionUnavailable v-else-if="session.state.status === 'unavailable'" />
    <AppShell v-else>
      <!-- A page of a resource loads it once; another resource at the same page is another page. -->
      <RouterView :key="route.path" />
    </AppShell>
  </template>
</template>
