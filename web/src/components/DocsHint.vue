<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { docsUrl } from '../docs';
import { t } from '../i18n';
</script>

<template>
  <p class="lede">
    <a :href="docsUrl" target="_blank" rel="noopener noreferrer">{{ t('docs.link') }} <span class="visually-hidden">{{ t('docs.newTab') }}</span></a>
  </p>
</template>
