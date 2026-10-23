<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useRoute } from 'vue-router';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { Event } from '../api/generated';
import { errorText } from '../api/messages';
import ResourceRef from '../components/ResourceRef.vue';
import SeverityBadge from '../components/SeverityBadge.vue';
import TimeStamp from '../components/TimeStamp.vue';
import UntrustedText from '../components/UntrustedText.vue';
import { t } from '../i18n';
import { useResourceNames } from '../resourceNames';

const route = useRoute();

const id = computed(() => String(route.params.id));
const event = ref<Event | undefined>();
const loading = ref(true);
const missing = ref(false);
const error = ref<string | undefined>();

const names = useResourceNames();

async function load(): Promise<void> {
  try {
    const loaded = (await api.call('getEvent', { path: { id: id.value } })).body;
    event.value = loaded;
    void names.resolve([loaded]);
  } catch (failure) {
    if (failure instanceof ApiError && failure.kind === 'not_found') {
      missing.value = true;
    } else {
      error.value = errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
    }
  } finally {
    loading.value = false;
  }
}

onMounted(load);
</script>

<template>
  <section>
    <p>
      <RouterLink v-if="event?.incident_id" :to="{ name: 'incident', params: { id: event.incident_id } }">{{ t('event.toIncident') }}</RouterLink>
      <RouterLink v-else :to="{ name: 'incidents' }">{{ t('incident.back') }}</RouterLink>
    </p>

    <p v-if="loading" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="missing" class="notice" role="status">{{ t('error.not_found') }}</p>

    <template v-else-if="event">
      <div class="page-head">
        <div>
          <h1>{{ t('event.title') }}</h1>
          <p class="badges">
            <span class="badge">{{ event.http !== null ? t('event.kind.http') : event.dns !== null ? t('event.kind.dns') : t('event.kind.sensor') }}</span>
            <SeverityBadge :severity="event.severity" />
          </p>
        </div>
      </div>

      <p class="hint">{{ t('event.personalData') }} {{ t('event.attackerText') }}</p>

      <div class="section panel">
        <dl class="definition">
          <dt>{{ t('field.resource') }}</dt>
          <dd><ResourceRef :type="event.resource_type" :id="event.resource_id" :entry="names.entries.value[names.key(event.resource_type, event.resource_id)]" /></dd>
          <dt v-if="event.honeytoken_type !== null">{{ t('field.type') }}</dt>
          <dd v-if="event.honeytoken_type !== null">{{ t(`honeytokenType.${event.honeytoken_type}`) }}</dd>
          <dt>{{ t('field.techniques') }}</dt>
          <dd class="mono">{{ event.techniques.length === 0 ? t('common.none') : event.techniques.join(', ') }}</dd>
          <dt>{{ t('field.recorded') }}</dt>
          <dd><TimeStamp :value="event.recorded_at" /></dd>
          <template v-if="event.occurred_at !== event.recorded_at">
            <dt>{{ t('event.occurred') }}</dt>
            <dd><TimeStamp :value="event.occurred_at" /></dd>
          </template>
          <dt>{{ t('event.clientIp') }}</dt>
          <dd class="mono">{{ event.client_ip ?? t('common.none') }}</dd>
        </dl>
      </div>

      <div v-if="event.http !== null" class="section panel">
        <h2>{{ t('event.kind.http') }}</h2>
        <dl class="definition">
          <dt>{{ t('event.method') }}</dt>
          <dd class="mono">{{ event.http.method }}</dd>
          <dt>{{ t('event.userAgent') }}</dt>
          <dd><UntrustedText :value="event.http.user_agent" /></dd>
          <dt>{{ t('event.referer') }}</dt>
          <dd><UntrustedText :value="event.http.referer" /></dd>
          <dt>{{ t('event.acceptLanguage') }}</dt>
          <dd><UntrustedText :value="event.http.accept_language" /></dd>
        </dl>
      </div>

      <div v-if="event.dns !== null" class="section panel">
        <h2>{{ t('event.kind.dns') }}</h2>
        <dl class="definition">
          <dt>{{ t('event.zone') }}</dt>
          <dd><UntrustedText :value="event.dns.zone" /></dd>
          <dt>{{ t('event.prefix') }}</dt>
          <dd><UntrustedText :value="event.dns.prefix" /></dd>
          <dt>{{ t('event.qtype') }}</dt>
          <dd><UntrustedText :value="event.dns.qtype" /></dd>
          <dt>{{ t('event.transport') }}</dt>
          <dd class="mono">{{ event.dns.transport }}</dd>
        </dl>
      </div>

      <div v-if="event.sensor !== null" class="section panel">
        <h2>{{ t('event.kind.sensor') }}</h2>
        <dl class="definition">
          <dt>{{ t('event.service') }}</dt>
          <dd>{{ t(`honeypotService.${event.sensor.service}`) }}</dd>
          <dt>{{ t('event.type') }}</dt>
          <dd>{{ t(`eventType.${event.sensor.event_type}`) }}</dd>
          <dt>{{ t('event.port') }}</dt>
          <dd class="mono">{{ event.sensor.port }}</dd>
          <dt>{{ t('event.duration') }}</dt>
          <dd>{{ t('unit.seconds', { count: (event.sensor.duration_ms / 1000).toFixed(1) }) }}</dd>
          <template v-if="event.sensor.client_version !== null">
            <dt>{{ t('event.clientVersion') }}</dt>
            <dd><UntrustedText :value="event.sensor.client_version" /></dd>
          </template>
          <template v-if="event.sensor.database !== null">
            <dt>{{ t('event.database') }}</dt>
            <dd><UntrustedText :value="event.sensor.database" /></dd>
          </template>
          <template v-if="event.sensor.application_name !== null">
            <dt>{{ t('event.application') }}</dt>
            <dd><UntrustedText :value="event.sensor.application_name" /></dd>
          </template>
          <template v-if="event.sensor.query !== null">
            <dt>{{ t('event.baseDn') }}</dt>
            <dd><UntrustedText :value="event.sensor.query.base_dn" /></dd>
            <dt>{{ t('event.searchFilter') }}</dt>
            <dd><UntrustedText :value="event.sensor.query.filter" /></dd>
          </template>
        </dl>

        <h3>{{ t('event.attempts') }}</h3>
        <p v-if="event.sensor.attempts.length === 0">{{ t('common.none') }}</p>
        <div v-else class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th scope="col">{{ t('event.username') }}</th>
                <th scope="col">{{ t('event.passwordLength') }}</th>
                <th scope="col">{{ t('event.keyFingerprint') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(attempt, index) in event.sensor.attempts" :key="index">
                <td><UntrustedText :value="attempt.username" /></td>
                <td>{{ attempt.password_length === null ? t('common.none') : t('event.characters', { count: attempt.password_length }) }}</td>
                <td><UntrustedText :value="attempt.key_fingerprint" /></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>

    <p v-else-if="error" class="notice notice-error" role="alert">{{ error }}</p>
  </section>
</template>

<style scoped>
.badges {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
  margin-top: 0.5rem;
}
</style>
