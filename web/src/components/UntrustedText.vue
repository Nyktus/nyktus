<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed } from 'vue';
import { t } from '../i18n';
import { segments } from '../untrusted';

// Text that an attacker chose: headers, user names, database names, search filters.
// It is drawn as text, in its own direction, so that letters of a right-to-left
// script cannot reorder what stands around them. It is never a link, never an
// attribute and never shortened: a shortened value hides what was sent.
const props = defineProps<{ value: string | null }>();

const parts = computed(() => (props.value === null ? [] : segments(props.value)));
</script>

<template>
  <span v-if="value === null" class="muted">{{ t('common.none') }}</span>
  <span v-else-if="value === ''" class="muted">{{ t('untrusted.empty') }}</span>
  <bdi v-else dir="ltr" class="untrusted mono"><template v-for="(part, index) in parts" :key="index"><span v-if="part.kind === 'hidden'" class="marker">{{ part.label }}</span><template v-else>{{ part.text }}</template></template></bdi>
</template>

<style scoped>
.untrusted {
  display: inline;
  unicode-bidi: isolate;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.marker {
  padding: 0 0.2em;
  border-radius: var(--radius-sm);
  background: var(--surface);
  border: 1px solid var(--line);
  color: var(--slate);
  font-size: 0.8em;
}

.muted {
  color: var(--slate);
}
</style>
