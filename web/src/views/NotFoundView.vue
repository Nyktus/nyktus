<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { t } from '../i18n';
</script>

<template>
  <section class="page">
    <h1>{{ t('notFound.title') }}</h1>
    <p>{{ t('notFound.body') }}</p>
    <p>
      <RouterLink :to="{ name: 'home' }">{{ t('notFound.back') }}</RouterLink>
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
