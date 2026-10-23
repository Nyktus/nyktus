<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Incident } from '../api/generated';
import { t } from '../i18n';

defineProps<{ status: Incident['status'] }>();
</script>

<template>
  <span class="badge" :class="{ 'badge-strong': status === 'open', 'badge-muted': status === 'closed' }">{{ t(`incidentStatus.${status}`) }}</span>
</template>
