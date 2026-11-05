<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed } from 'vue';
import type { CatalogDeception } from '../api/generated';
import { t } from '../i18n';
import DeceptionSlots from './DeceptionSlots.vue';
import MarkdownView from './MarkdownView';
import TimeStamp from './TimeStamp.vue';

// One deception of a scenario: what it asks for, its files, and its guide behind a fold. The catalog says all of this
// when it is asked, so what the scenario keeps is the identifier and the time it joined.
const props = defineProps<{
  scenarioId: string;
  deceptionId: string;
  addedAt: string;
  /** The title from the list of the catalog, in the language of the console; without it, the identifier stands. */
  title?: string;
  /** The catalog does not know the deception any more. */
  gone: boolean;
  /** The detail from the catalog, `failed` if it could not be read, nothing while it is on its way. */
  detail?: CatalogDeception | 'failed';
  canRemove: boolean;
  busy: boolean;
}>();

defineEmits<{ remove: []; retry: [] }>();

// The list names a deception first; when it could not be read, the detail does.
const shownTitle = computed(() => props.title ?? (typeof props.detail === 'object' ? props.detail.title : undefined) ?? props.deceptionId);
</script>

<template>
  <article class="story">
    <div class="head">
      <h3>
        <span v-if="gone" class="mono">{{ deceptionId }}</span>
        <RouterLink v-else :to="{ name: 'catalog-deception', params: { id: deceptionId } }">{{ shownTitle }}</RouterLink>
      </h3>
      <button v-if="canRemove" class="button button-ghost small" type="button" :disabled="busy" @click="$emit('remove')">
        {{ t('scenarios.stories.remove') }}
      </button>
    </div>
    <p class="hint">{{ t('scenarios.stories.added') }} <TimeStamp :value="addedAt" /></p>

    <p v-if="gone" class="notice" role="status">{{ t('scenarios.stories.gone') }}</p>
    <template v-else-if="detail !== undefined && detail !== 'failed'">
      <DeceptionSlots :deception="detail" :under="3" :scenario="scenarioId" />
      <details class="guide">
        <summary>{{ t('scenarios.guide') }}</summary>
        <MarkdownView :source="detail.guide" :under="3" />
      </details>
    </template>
    <div v-else-if="detail === 'failed'" class="notice notice-error" role="alert">
      {{ t('scenarios.stories.loadFailed') }}
      <button class="button button-ghost small" type="button" @click="$emit('retry')">{{ t('scenarios.stories.retry') }}</button>
    </div>
    <p v-else role="status">{{ t('app.loading') }}</p>
  </article>
</template>

<style scoped>
.story {
  margin-top: 0.9rem;
  padding-top: 0.9rem;
  border-top: 1px solid var(--line-soft);
}

.story h3 {
  font-size: 0.95rem;
}

.head {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  align-items: center;
  justify-content: space-between;
}

.guide {
  margin-top: 0.9rem;
}

.guide summary {
  cursor: pointer;
  font-weight: 600;
}

.hint {
  color: var(--slate);
}
</style>
