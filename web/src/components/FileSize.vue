<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed } from 'vue';
import { formatSize } from '../format';
import { locale, t } from '../i18n';

const props = defineProps<{ bytes: number }>();

const text = computed(() => {
  const size = formatSize(props.bytes, locale.value);
  return size.unit === 'bytes' ? t('unit.bytes', { count: size.count }) : size.unit === 'kib' ? t('unit.kib', { count: size.count }) : t('unit.mib', { count: size.count });
});
</script>

<template>{{ text }}</template>
