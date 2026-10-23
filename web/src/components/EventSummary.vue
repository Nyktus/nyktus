<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Event } from '../api/generated';
import { t } from '../i18n';
import UntrustedText from './UntrustedText.vue';

// The member that is filled says what happened; `channel` only repeats it.
defineProps<{ event: Event }>();
</script>

<template>
  <span v-if="event.http !== null" class="summary"><span class="mono">{{ event.http.method }}</span> <UntrustedText :value="event.http.user_agent" /></span>
  <span v-else-if="event.dns !== null" class="summary"><UntrustedText :value="event.dns.qtype" /> <UntrustedText :value="event.dns.prefix" /></span>
  <span v-else-if="event.sensor !== null" class="summary">
    {{ t(`honeypotService.${event.sensor.service}`) }}: {{ t(`eventType.${event.sensor.event_type}`) }}<template v-if="event.sensor.attempts.length > 0">, <UntrustedText :value="event.sensor.attempts[0]?.username ?? null" /></template>
  </span>
</template>
