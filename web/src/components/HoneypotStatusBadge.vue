<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Honeypot } from '../api/generated';
import { t } from '../i18n';

defineProps<{ status: Honeypot['status'] }>();
</script>

<template>
  <span class="badge" :class="{ 'badge-muted': status !== 'online' }">{{ t(`honeypotStatus.${status}`) }}</span>
</template>
