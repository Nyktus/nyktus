<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, shallowRef, useId, type ShallowRef } from 'vue';
import { api } from '../api/client';
import DocsHint from '../components/DocsHint.vue';
import HoneypotStatusBadge from '../components/HoneypotStatusBadge.vue';
import IncidentStatusBadge from '../components/IncidentStatusBadge.vue';
import SeverityBadge from '../components/SeverityBadge.vue';
import TimeStamp from '../components/TimeStamp.vue';
import { locale, t } from '../i18n';
import { countLabel, pageLimit, summarizeHoneypots, summarizeHoneytokens, summarizeIncidents, type Counted } from '../overview';
import { session } from '../session';
import type { Honeypot, Honeytoken, Incident } from '../api/generated';

/** How often the page asks again while it is visible, in milliseconds. */
const pollEvery = 60_000;

const ids = useId();
const canIncidents = computed(() => session.can('incidents:read'));
const canHoneypots = computed(() => session.can('honeypots:read'));
const canHoneytokens = computed(() => session.can('honeytokens:read'));

// Each list stands alone: one that cannot be read leaves the others as they are.
const incidents = shallowRef<Counted<Incident> | undefined>();
const honeypots = shallowRef<Counted<Honeypot> | undefined>();
const honeytokens = shallowRef<Counted<Honeytoken> | undefined>();
const failed = reactive({ incidents: false, honeypots: false, honeytokens: false });
const busy = ref(false);

async function fill<T>(target: ShallowRef<Counted<T> | undefined>, key: keyof typeof failed, ask: () => Promise<{ items: T[]; next: string | undefined }>): Promise<void> {
  try {
    const page = await ask();
    target.value = { items: page.items, more: page.next !== undefined };
    failed[key] = false;
  } catch {
    // What was shown before stays, and the tile says that it may be out of date.
    failed[key] = true;
  }
}

async function load(): Promise<void> {
  if (busy.value) {
    return;
  }
  busy.value = true;
  try {
    await Promise.all([
      canIncidents.value
        ? fill(incidents, 'incidents', async () => {
            const { body } = await api.call('listIncidents', { query: { limit: pageLimit, status: 'open,acknowledged' } });
            return { items: body.incidents, next: body.next_cursor };
          })
        : undefined,
      canHoneypots.value
        ? fill(honeypots, 'honeypots', async () => {
            const { body } = await api.call('listHoneypots', { query: { limit: pageLimit } });
            return { items: body.honeypots, next: body.next_cursor };
          })
        : undefined,
      canHoneytokens.value
        ? fill(honeytokens, 'honeytokens', async () => {
            const { body } = await api.call('listHoneytokens', { query: { limit: pageLimit } });
            return { items: body.honeytokens, next: body.next_cursor };
          })
        : undefined,
    ]);
  } finally {
    busy.value = false;
  }
}

let timer: ReturnType<typeof setInterval> | undefined;

onMounted(() => {
  void load();
  timer = setInterval(() => {
    if (document.visibilityState === 'visible') {
      void load();
    }
  }, pollEvery);
});
onBeforeUnmount(() => {
  clearInterval(timer);
});

const incidentSummary = computed(() => (incidents.value === undefined ? undefined : summarizeIncidents(incidents.value)));
const honeypotSummary = computed(() => (honeypots.value === undefined ? undefined : summarizeHoneypots(honeypots.value)));
const honeytokenSummary = computed(() => (honeytokens.value === undefined ? undefined : summarizeHoneytokens(honeytokens.value)));

const number = (n: number): string => new Intl.NumberFormat(locale.value).format(n);
</script>

<template>
  <section class="overview">
    <div class="page-head">
      <div>
        <h1>{{ t('home.title') }}</h1>
        <DocsHint />
      </div>
      <button class="button button-ghost" type="button" :disabled="busy" @click="load">{{ t('common.refresh') }}</button>
    </div>

    <div class="tiles">
      <section v-if="canIncidents" class="panel tile tile-incidents" :aria-labelledby="`${ids}-incidents`">
        <header class="tile-head">
          <h2 :id="`${ids}-incidents`">{{ t('nav.incidents') }}</h2>
          <RouterLink :to="{ name: 'incidents' }">{{ t('home.incidents.all') }}</RouterLink>
        </header>
        <p v-if="failed.incidents && incidentSummary !== undefined" class="notice" role="status">{{ t('home.stale') }}</p>
        <p v-if="failed.incidents && incidentSummary === undefined" class="notice notice-error" role="alert">{{ t('home.loadFailed') }}</p>
        <p v-else-if="incidentSummary === undefined" role="status">{{ t('app.loading') }}</p>
        <template v-else>
          <dl class="counts">
            <div class="count" :class="{ alarm: incidentSummary.open > 0 }">
              <dt>{{ t('incidentStatus.open') }}</dt>
              <dd>{{ countLabel(incidentSummary.open, incidentSummary.more, number) }}</dd>
            </div>
            <div class="count">
              <dt>{{ t('incidentStatus.acknowledged') }}</dt>
              <dd>{{ countLabel(incidentSummary.acknowledged, incidentSummary.more, number) }}</dd>
            </div>
          </dl>
          <ul v-if="incidentSummary.lead.length > 0" class="rows">
            <li v-for="incident in incidentSummary.lead" :key="incident.id" class="row row-incident">
              <SeverityBadge :severity="incident.severity" />
              <div class="what">
                <RouterLink :to="{ name: 'incident', params: { id: incident.id } }">{{ incident.resource_name }}</RouterLink>
                <span class="meta">
                  {{ t(`resourceType.${incident.resource_type}`) }} · {{ t('field.events') }} {{ number(incident.event_count) }} · <TimeStamp :value="incident.last_event_at" />
                </span>
              </div>
              <IncidentStatusBadge v-if="incident.status !== 'open'" :status="incident.status" />
            </li>
          </ul>
          <div v-else class="empty">
            <p>{{ t('incidents.emptyActive') }}</p>
          </div>
          <p v-if="incidentSummary.more" class="meta">{{ t('home.incidents.truncated') }}</p>
        </template>
      </section>

      <section v-if="canHoneypots" class="panel tile" :aria-labelledby="`${ids}-honeypots`">
        <header class="tile-head">
          <h2 :id="`${ids}-honeypots`">{{ t('nav.honeypots') }}</h2>
          <RouterLink :to="{ name: 'honeypots' }">{{ t('home.honeypots.all') }}</RouterLink>
        </header>
        <p v-if="failed.honeypots && honeypotSummary !== undefined" class="notice" role="status">{{ t('home.stale') }}</p>
        <p v-if="failed.honeypots && honeypotSummary === undefined" class="notice notice-error" role="alert">{{ t('home.loadFailed') }}</p>
        <p v-else-if="honeypotSummary === undefined" role="status">{{ t('app.loading') }}</p>
        <div v-else-if="honeypots !== undefined && honeypots.items.length === 0" class="empty">
          <p>{{ t('home.honeypots.empty') }}</p>
          <p v-if="session.can('honeypots:write')">
            <RouterLink class="button button-primary small" :to="{ name: 'honeypot-new' }">{{ t('honeypots.new') }}</RouterLink>
          </p>
        </div>
        <template v-else>
          <dl class="counts">
            <div class="count">
              <dt>{{ t('honeypotStatus.online') }}</dt>
              <dd>{{ countLabel(honeypotSummary.online, honeypotSummary.more, number) }}</dd>
            </div>
            <div class="count" :class="{ alarm: honeypotSummary.offline > 0 }">
              <dt>{{ t('honeypotStatus.offline') }}</dt>
              <dd>{{ countLabel(honeypotSummary.offline, honeypotSummary.more, number) }}</dd>
            </div>
            <div class="count">
              <dt>{{ t('honeypotStatus.never') }}</dt>
              <dd>{{ countLabel(honeypotSummary.never, honeypotSummary.more, number) }}</dd>
            </div>
            <div v-if="honeypotSummary.disabled > 0" class="count">
              <dt>{{ t('state.disabled') }}</dt>
              <dd>{{ countLabel(honeypotSummary.disabled, honeypotSummary.more, number) }}</dd>
            </div>
          </dl>
          <div v-if="honeypotSummary.silent.length > 0">
            <h3>{{ t('home.honeypots.attention') }}</h3>
            <ul class="rows">
              <li v-for="honeypot in honeypotSummary.silent" :key="honeypot.id" class="row">
                <div class="what">
                  <RouterLink :to="{ name: 'honeypot', params: { id: honeypot.id } }">{{ honeypot.name }}</RouterLink>
                  <span class="meta">
                    {{ t(`honeypotService.${honeypot.service}`) }} ·
                    <template v-if="honeypot.last_seen_at !== null">{{ t('honeypots.lastSeen') }} <TimeStamp :value="honeypot.last_seen_at" /></template>
                    <template v-else>{{ t('honeypots.never') }}</template>
                  </span>
                </div>
                <HoneypotStatusBadge :status="honeypot.status" />
              </li>
            </ul>
          </div>
        </template>
      </section>

      <section v-if="canHoneytokens" class="panel tile" :aria-labelledby="`${ids}-honeytokens`">
        <header class="tile-head">
          <h2 :id="`${ids}-honeytokens`">{{ t('nav.honeytokens') }}</h2>
          <RouterLink :to="{ name: 'honeytokens' }">{{ t('home.honeytokens.all') }}</RouterLink>
        </header>
        <p v-if="failed.honeytokens && honeytokenSummary !== undefined" class="notice" role="status">{{ t('home.stale') }}</p>
        <p v-if="failed.honeytokens && honeytokenSummary === undefined" class="notice notice-error" role="alert">{{ t('home.loadFailed') }}</p>
        <p v-else-if="honeytokenSummary === undefined" role="status">{{ t('app.loading') }}</p>
        <div v-else-if="honeytokens !== undefined && honeytokens.items.length === 0" class="empty">
          <p>{{ t('home.honeytokens.empty') }}</p>
          <p class="meta">{{ t('home.honeytokens.emptyHint') }}</p>
          <p class="actions-row">
            <RouterLink v-if="session.can('catalog:read')" class="button button-primary small" :to="{ name: 'catalog' }">{{ t('home.honeytokens.fromCatalog') }}</RouterLink>
            <RouterLink v-if="session.can('honeytokens:write')" class="button button-ghost small" :to="{ name: 'honeytoken-new' }">{{ t('honeytokens.new') }}</RouterLink>
          </p>
        </div>
        <template v-else>
          <dl class="counts">
            <div class="count">
              <dt>{{ t('home.honeytokens.active') }}</dt>
              <dd>{{ countLabel(honeytokenSummary.active, honeytokenSummary.more, number) }}</dd>
            </div>
            <div class="count">
              <dt>{{ t('state.disabled') }}</dt>
              <dd>{{ countLabel(honeytokenSummary.disabled, honeytokenSummary.more, number) }}</dd>
            </div>
          </dl>
          <div v-if="honeytokenSummary.byType.length > 0">
            <h3>{{ t('home.honeytokens.byType') }}</h3>
            <ul class="types">
              <li v-for="entry in honeytokenSummary.byType" :key="entry.type" class="badge">{{ t(`honeytokenType.${entry.type}`) }} {{ number(entry.count) }}</li>
            </ul>
          </div>
        </template>
      </section>
    </div>
  </section>
</template>

<style scoped>
.tiles {
  display: grid;
  gap: 1rem;
}

@media (min-width: 52rem) {
  .tiles {
    grid-template-columns: minmax(0, 3fr) minmax(0, 2fr);
    align-items: start;
  }

  /* What needs the operator first takes the wide column, beside the two that show what is watching. */
  .tile-incidents {
    grid-row: span 2;
  }
}

.tile {
  display: grid;
  gap: 1rem;
  padding: 1.1rem 1.25rem 1.25rem;
}

.tile-head {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  justify-content: space-between;
  gap: 0.25rem 1rem;
}

.tile-head a {
  font-size: 0.875rem;
  font-weight: 600;
}

h3 {
  margin-bottom: 0.4rem;
  color: var(--slate);
  font-size: 0.8125rem;
  font-weight: 600;
  letter-spacing: 0;
}

/* The figures are the labels of the lists below them, not the point of the page. */
.counts {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(5.25rem, 1fr));
  gap: 0.5rem;
  margin: 0;
}

.count {
  display: grid;
  gap: 0.1rem;
  padding: 0.55rem 0.85rem;
  border: 1px solid var(--line-soft);
  border-radius: var(--radius-sm);
  background: var(--surface);
}

.count dt {
  color: var(--slate);
  font-size: 0.8125rem;
  font-weight: 600;
}

.count dd {
  margin: 0;
  font-size: 1.5rem;
  font-weight: 700;
  line-height: 1.2;
  font-variant-numeric: tabular-nums;
}

/* Something that needs the operator now: the same danger the badges of an incident use, as text and as ground. */
.count.alarm {
  border-color: var(--danger);
  background: var(--danger-soft);
  color: var(--danger);
}

.count.alarm dt {
  color: var(--danger);
}

.rows {
  display: grid;
  margin: 0;
  padding: 0;
  list-style: none;
}

.row {
  display: flex;
  align-items: flex-start;
  gap: 0.75rem;
  padding: 0.65rem 0;
  border-top: 1px solid var(--line-soft);
}

.row-incident {
  display: grid;
  grid-template-columns: 4.75rem minmax(0, 1fr) auto;
}

.row-incident > :first-child {
  justify-self: start;
}

.row .what {
  display: grid;
  flex: 1;
  min-width: 0;
}

.row a {
  font-weight: 600;
  overflow-wrap: anywhere;
}

.meta {
  color: var(--slate);
  font-size: 0.8125rem;
}

/* A time that breaks in the middle reads as two. */
.meta time {
  white-space: nowrap;
}

.empty {
  display: grid;
  gap: 0.5rem;
  justify-items: start;
}

.types {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
  margin: 0;
  padding: 0;
  list-style: none;
}
</style>
