<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { formatDateTime } from '../format';
import { locale } from '../i18n';

defineProps<{ value: string }>();
</script>

<template>
  <time :datetime="value" :title="`${value} (UTC)`">{{ formatDateTime(value, locale) }}</time>
</template>
