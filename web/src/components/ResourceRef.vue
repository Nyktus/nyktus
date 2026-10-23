<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { t } from '../i18n';
import type { ResourceEntry, ResourceType } from '../resourceNames';

defineProps<{ type: ResourceType; id: string; entry: ResourceEntry | undefined }>();
</script>

<template>
  <span class="ref">
    <span class="kind">{{ t(`resourceType.${type}`) }}</span>
    <RouterLink v-if="entry?.state === 'named'" :to="{ name: type, params: { id } }">{{ entry.name }}</RouterLink>
    <template v-else-if="entry?.state === 'gone'">
      <span>{{ t('resource.gone') }}</span>
      <code class="mono id">{{ id }}</code>
    </template>
    <code v-else class="mono id">{{ id }}</code>
  </span>
</template>

<style scoped>
.ref {
  display: inline-flex;
  flex-wrap: wrap;
  gap: 0.2rem 0.5rem;
  align-items: baseline;
}

.kind {
  color: var(--slate);
  font-size: 0.8125rem;
}

.id {
  font-size: 0.75rem;
  overflow-wrap: anywhere;
}
</style>
