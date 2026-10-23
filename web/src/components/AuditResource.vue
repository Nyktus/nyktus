<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed } from 'vue';
import type { AuditResource } from '../api/generated';

const props = defineProps<{ resource: AuditResource; action: string }>();

/** The pages that show a resource of a type, as far as the console has one. */
const pages: Record<string, string> = {
  user: 'user',
  honeytoken: 'honeytoken',
  honeypot: 'honeypot',
  scenario: 'scenario',
  artifact: 'artifact',
  alert_channel: 'alert-channel',
  incident: 'incident',
};

// What an entry records as deleted has no page any more: the identifier is all that is left of it.
const page = computed(() => (props.action.endsWith('.delete') ? undefined : pages[props.resource.type]));
</script>

<template>
  <span class="resource">
    <span class="type mono">{{ resource.type }}</span>
    <RouterLink v-if="page" :to="{ name: page, params: { id: resource.id } }" class="id mono">{{ resource.id }}</RouterLink>
    <code v-else class="id mono">{{ resource.id }}</code>
  </span>
</template>

<style scoped>
.resource {
  display: grid;
  gap: 0.1rem;
}

.type {
  color: var(--slate);
  font-size: 0.8125rem;
}

.id {
  font-size: 0.75rem;
  overflow-wrap: anywhere;
}
</style>
