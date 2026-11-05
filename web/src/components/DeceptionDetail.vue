<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { CatalogDeception } from '../api/generated';
import { t } from '../i18n';
import DeceptionSlots from './DeceptionSlots.vue';
import MarkdownView from './MarkdownView';

// The guide, then what the deception asks for and its files. The level of the heading above is `under`: the page title of
// the catalog is a level 1.
const props = withDefaults(defineProps<{ deception: CatalogDeception; under?: number }>(), { under: 1 });
</script>

<template>
  <div class="detail">
    <component :is="`h${Math.min(6, props.under + 1)}`" class="part">{{ t('catalog.guide') }}</component>
    <MarkdownView :source="deception.guide" :under="props.under + 1" />
    <DeceptionSlots :deception="deception" :under="props.under" />
  </div>
</template>
