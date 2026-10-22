<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { onBeforeUnmount, ref } from 'vue';
import { t } from '../i18n';

const props = defineProps<{ value: string }>();

const copied = ref(false);
let timer: ReturnType<typeof setTimeout> | undefined;

// The clipboard is only there on a page that the browser counts as secure.
const available = typeof navigator !== 'undefined' && navigator.clipboard !== undefined;

async function copy(): Promise<void> {
  try {
    await navigator.clipboard.writeText(props.value);
  } catch {
    return;
  }
  copied.value = true;
  clearTimeout(timer);
  timer = setTimeout(() => {
    copied.value = false;
  }, 2000);
}

onBeforeUnmount(() => {
  clearTimeout(timer);
});
</script>

<template>
  <button v-if="available" class="button button-ghost small" type="button" @click="copy">
    {{ copied ? t('common.copied') : t('common.copy') }}
  </button>
</template>
