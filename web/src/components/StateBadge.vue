<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { t } from '../i18n';

defineProps<{ enabled: boolean }>();
</script>

<template>
  <span class="badge" :class="{ 'badge-muted': !enabled }">{{ enabled ? t('state.enabled') : t('state.disabled') }}</span>
</template>
