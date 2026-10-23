<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { User } from '../api/generated';
import { t } from '../i18n';

defineProps<{ status: User['status'] }>();
</script>

<template>
  <span class="badge" :class="{ 'badge-muted': status === 'deactivated' }">{{ t(`userStatus.${status}`) }}</span>
</template>
