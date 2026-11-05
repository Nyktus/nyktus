<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, ref } from 'vue';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { CatalogDeception } from '../api/generated';
import { errorText } from '../api/messages';
import { saveFile } from '../download';
import { t } from '../i18n';
import { session } from '../session';
import { honeypotSlotQuery, honeytokenSlotQuery } from '../slotPrefill';
import FileSize from './FileSize.vue';
import SeverityBadge from './SeverityBadge.vue';

// What a deception asks for and the example files it brings. With a scenario, each slot offers to create what it asks for
// in that scenario. The level of the heading above is `under`.
const props = withDefaults(defineProps<{ deception: CatalogDeception; under?: number; scenario?: string }>(), { under: 1, scenario: undefined });
const heading = (below: number): string => `h${Math.min(6, props.under + below)}`;

// Offering to create needs a scenario to create in; the cells of the rows that hold the links exist only with one.
const canCreateHoneytoken = computed(() => session.can('honeytokens:write'));
const canCreateHoneypot = computed(() => session.can('honeypots:write'));

const error = ref<string | undefined>();

// The file is handed to the browser to save and never opened in the console: it can be HTML or the
// configuration of a tool.
async function download(name: string): Promise<void> {
  error.value = undefined;
  try {
    const { body } = await api.call('downloadCatalogDeceptionFile', { path: { id: props.deception.id, name } });
    saveFile(body, name);
  } catch (failure) {
    error.value = `${t('catalog.downloadFailed')} ${errorText(failure instanceof ApiError ? failure : new ApiError('server', 0))}`;
  }
}
</script>

<template>
  <div>
    <component :is="heading(1)" class="part">{{ t('catalog.slots') }}</component>
    <p v-if="deception.honeytokens.length === 0 && deception.honeypots.length === 0" class="hint">{{ t('catalog.slots.none') }}</p>
    <template v-if="deception.honeytokens.length > 0">
      <component :is="heading(2)" class="subpart">{{ t('catalog.honeytokens') }}</component>
      <div class="table-wrap">
        <table class="table">
          <tbody>
            <tr v-for="(honeytoken, index) in deception.honeytokens" :key="index">
              <td>{{ honeytoken.label }}</td>
              <td>{{ t(`honeytokenType.${honeytoken.type}`) }}</td>
              <td><SeverityBadge :severity="honeytoken.severity" /></td>
              <td class="mono">{{ honeytoken.techniques.join(', ') }}</td>
              <td v-if="scenario !== undefined" class="end">
                <RouterLink
                  v-if="canCreateHoneytoken"
                  class="button button-ghost small"
                  :aria-label="t('scenarios.slot.createFor', { label: honeytoken.label })"
                  :to="{ name: 'honeytoken-new', query: honeytokenSlotQuery(scenario, honeytoken) }"
                >
                  {{ t('scenarios.slot.create') }}
                </RouterLink>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
    <template v-if="deception.honeypots.length > 0">
      <component :is="heading(2)" class="subpart">{{ t('catalog.honeypots') }}</component>
      <div class="table-wrap">
        <table class="table">
          <tbody>
            <tr v-for="(honeypot, index) in deception.honeypots" :key="index">
              <td>{{ honeypot.label }}</td>
              <td>{{ t(`honeypotService.${honeypot.service}`) }}</td>
              <td v-if="scenario !== undefined" class="end">
                <RouterLink
                  v-if="canCreateHoneypot"
                  class="button button-ghost small"
                  :aria-label="t('scenarios.slot.createFor', { label: honeypot.label })"
                  :to="{ name: 'honeypot-new', query: honeypotSlotQuery(scenario, honeypot) }"
                >
                  {{ t('scenarios.slot.create') }}
                </RouterLink>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <template v-if="deception.files.length > 0">
      <component :is="heading(1)" class="part">{{ t('catalog.files') }}</component>
      <p class="hint">
        {{ t('catalog.files.hint') }}
        <template v-if="scenario !== undefined && deception.honeytokens.length > 0">{{ t('scenarios.files.where', { table: t('scenarios.members.honeytokens') }) }}</template>
      </p>
      <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>
      <div class="table-wrap">
        <table class="table">
          <tbody>
            <tr v-for="file in deception.files" :key="file.name">
              <td class="mono"><bdi>{{ file.name }}</bdi></td>
              <td>{{ t(`fileFormat.${file.format}`) }}</td>
              <td><FileSize :bytes="file.size" /></td>
              <td class="end">
                <button class="button button-ghost small" type="button" @click="download(file.name)">{{ t('catalog.download') }}</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </div>
</template>

<style scoped>
.hint {
  color: var(--slate);
  font-size: 0.8125rem;
}

.subpart {
  font-size: 0.95rem;
}

.end {
  text-align: right;
}
</style>
