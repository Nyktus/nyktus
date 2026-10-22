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
  <RouterView v-if="route.meta.public" />
  <SessionUnavailable v-else-if="session.state.status === 'unavailable'" />
  <AppShell v-else>
    <RouterView />
  </AppShell>
</template>
