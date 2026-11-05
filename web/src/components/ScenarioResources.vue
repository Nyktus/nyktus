<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { Honeypot, Honeytoken } from '../api/generated';
import { errorText } from '../api/messages';
import { t } from '../i18n';
import { session } from '../session';
import { usePagedList } from '../usePagedList';
import CopyButton from './CopyButton.vue';
import SeverityBadge from './SeverityBadge.vue';
import StateBadge from './StateBadge.vue';

// The honeytokens and honeypots of a scenario. A resource knows its scenario and nothing of the deception that asked for
// it, so they stand once for the whole scenario. A honeytoken shows the value to place in a file or a command.
const props = defineProps<{ scenarioId: string }>();

const canWriteHoneytokens = computed(() => session.can('honeytokens:write'));
const canWriteHoneypots = computed(() => session.can('honeypots:write'));

const honeytokens = usePagedList<Honeytoken>(async (cursor) => {
  const { body } = await api.call('listHoneytokens', { query: { limit: 50, cursor, scenario_id: props.scenarioId } });
  return { items: body.honeytokens, next: body.next_cursor };
});
const honeypots = usePagedList<Honeypot>(async (cursor) => {
  const { body } = await api.call('listHoneypots', { query: { limit: 50, cursor, scenario_id: props.scenarioId } });
  return { items: body.honeypots, next: body.next_cursor };
});

const detaching = ref(false);
const error = ref<string | undefined>();

// What is to be placed: the address of a URL honeytoken, the names of a DNS honeytoken under each of its zones.
function values(honeytoken: Honeytoken): string[] {
  return honeytoken.trigger_url === null ? honeytoken.trigger_names : [honeytoken.trigger_url];
}

async function detach(kind: 'honeytoken' | 'honeypot', resourceId: string): Promise<void> {
  detaching.value = true;
  error.value = undefined;
  try {
    if (kind === 'honeytoken') {
      await api.call('detachHoneytokenScenario', { path: { id: resourceId } });
      await honeytokens.reload();
    } else {
      await api.call('detachHoneypotScenario', { path: { id: resourceId } });
      await honeypots.reload();
    }
  } catch (failure) {
    error.value = errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
  } finally {
    detaching.value = false;
  }
}

onMounted(() => {
  void honeytokens.reload();
  void honeypots.reload();
});
</script>

<template>
  <div>
    <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>

    <div class="section panel">
      <div class="head">
        <h2>{{ t('scenarios.members.honeytokens') }}</h2>
        <RouterLink v-if="canWriteHoneytokens" class="button button-ghost small" :to="{ name: 'honeytoken-new', query: { scenario: scenarioId } }">
          {{ t('scenarios.members.addHoneytoken') }}
        </RouterLink>
      </div>
      <p v-if="honeytokens.error.value" class="notice notice-error" role="alert">{{ t('scenarios.members.loadFailed') }}</p>
      <p v-else-if="honeytokens.loaded.value && honeytokens.items.value.length === 0" class="hint">{{ t('scenarios.members.none') }}</p>
      <div v-else-if="honeytokens.items.value.length > 0" class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th scope="col">{{ t('field.name') }}</th>
              <th scope="col">{{ t('field.type') }}</th>
              <th scope="col">{{ t('field.state') }}</th>
              <th scope="col">{{ t('field.severity') }}</th>
              <th scope="col">{{ t('scenarios.members.value') }}</th>
              <th scope="col"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="honeytoken in honeytokens.items.value" :key="honeytoken.id">
              <td><RouterLink :to="{ name: 'honeytoken', params: { id: honeytoken.id } }">{{ honeytoken.name }}</RouterLink></td>
              <td>{{ t(`honeytokenType.${honeytoken.type}`) }}</td>
              <td><StateBadge :enabled="honeytoken.enabled" /></td>
              <td><SeverityBadge :severity="honeytoken.severity" /></td>
              <td>
                <div v-for="value in values(honeytoken)" :key="value" class="value">
                  <span class="mono">{{ value }}</span>
                  <CopyButton :value="value" :describe="value" />
                </div>
              </td>
              <td class="end">
                <button v-if="canWriteHoneytokens" class="button button-ghost small" type="button" :disabled="detaching" @click="detach('honeytoken', honeytoken.id)">
                  {{ t('scenarios.remove') }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-if="honeytokens.next.value !== undefined">
        <button class="button button-ghost small" type="button" :disabled="honeytokens.loading.value" @click="honeytokens.more">{{ t('common.loadMore') }}</button>
      </p>
    </div>

    <div class="section panel">
      <div class="head">
        <h2>{{ t('scenarios.members.honeypots') }}</h2>
        <RouterLink v-if="canWriteHoneypots" class="button button-ghost small" :to="{ name: 'honeypot-new', query: { scenario: scenarioId } }">
          {{ t('scenarios.members.addHoneypot') }}
        </RouterLink>
      </div>
      <p v-if="honeypots.error.value" class="notice notice-error" role="alert">{{ t('scenarios.members.loadFailed') }}</p>
      <p v-else-if="honeypots.loaded.value && honeypots.items.value.length === 0" class="hint">{{ t('scenarios.members.none') }}</p>
      <div v-else-if="honeypots.items.value.length > 0" class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th scope="col">{{ t('field.name') }}</th>
              <th scope="col">{{ t('field.type') }}</th>
              <th scope="col">{{ t('field.state') }}</th>
              <th scope="col">{{ t('field.severity') }}</th>
              <th scope="col"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="honeypot in honeypots.items.value" :key="honeypot.id">
              <td><RouterLink :to="{ name: 'honeypot', params: { id: honeypot.id } }">{{ honeypot.name }}</RouterLink></td>
              <td>{{ t(`honeypotService.${honeypot.service}`) }}</td>
              <td><StateBadge :enabled="honeypot.enabled" /></td>
              <td><SeverityBadge :severity="honeypot.severity" /></td>
              <td class="end">
                <button v-if="canWriteHoneypots" class="button button-ghost small" type="button" :disabled="detaching" @click="detach('honeypot', honeypot.id)">
                  {{ t('scenarios.remove') }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-if="honeypots.next.value !== undefined">
        <button class="button button-ghost small" type="button" :disabled="honeypots.loading.value" @click="honeypots.more">{{ t('common.loadMore') }}</button>
      </p>
    </div>
  </div>
</template>

<style scoped>
.head {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  align-items: center;
  justify-content: space-between;
}

.end {
  text-align: right;
}

.hint {
  color: var(--slate);
}

.value {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  align-items: center;
}
</style>
