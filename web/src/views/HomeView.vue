<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed } from 'vue';
import { t } from '../i18n';
import { session } from '../session';

const user = computed(() => session.state.session?.user);
</script>

<template>
  <section v-if="user" class="page">
    <h1>{{ t('home.title') }}</h1>
    <p>{{ t('home.welcome', { name: user.display_name }) }}</p>
    <p>{{ t('home.role', { role: t(`role.${user.role}`) }) }}</p>
  </section>
</template>

<style scoped>
.page {
  display: grid;
  gap: 0.75rem;
  max-width: 36rem;
}
</style>
