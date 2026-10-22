<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Honeytoken } from '../api/generated';
import { t } from '../i18n';

defineProps<{ severity: Honeytoken['severity'] }>();
</script>

<template>
  <span class="badge" :class="{ 'badge-strong': severity === 'high' || severity === 'critical' }">{{ t(`severity.${severity}`) }}</span>
</template>
