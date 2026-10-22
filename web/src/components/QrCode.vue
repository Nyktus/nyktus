<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed } from 'vue';
import { encode, quietZone } from '../qr';

const props = defineProps<{ text: string; label: string }>();

const qr = computed(() => encode(props.text));
const box = computed(() => (qr.value === undefined ? 0 : qr.value.size + 2 * quietZone));
</script>

<template>
  <svg
    v-if="qr"
    class="qr"
    role="img"
    :aria-label="label"
    :viewBox="`${-quietZone} ${-quietZone} ${box} ${box}`"
    shape-rendering="crispEdges"
  >
    <rect :x="-quietZone" :y="-quietZone" :width="box" :height="box" fill="#ffffff" />
    <path :d="qr.path" fill="#13201a" />
  </svg>
</template>

<style scoped>
.qr {
  display: block;
  width: 12rem;
  max-width: 100%;
  height: auto;
  border: 1px solid var(--line);
  border-radius: var(--radius-sm);
}
</style>
