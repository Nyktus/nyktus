<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import markUrl from '../assets/mark.svg';

defineProps<{ title: string }>();
</script>

<template>
  <main class="stage">
    <div class="card panel">
      <div class="brand">
        <img :src="markUrl" alt="" width="36" height="36" />
        <span>Nyktus</span>
      </div>
      <h1>{{ title }}</h1>
      <slot />
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
