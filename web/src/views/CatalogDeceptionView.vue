<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { CatalogDeception } from '../api/generated';
import { errorText } from '../api/messages';
import DeceptionDetail from '../components/DeceptionDetail.vue';
import { engageLabel, useEngageNames } from '../engageNames';
import { locale, t } from '../i18n';
import { session } from '../session';

const route = useRoute();
const router = useRouter();

const id = computed(() => String(route.params.id));
const deception = ref<CatalogDeception | undefined>();
const loading = ref(true);
const missing = ref(false);
const error = ref<string | undefined>();
const loadError = ref<string | undefined>();
const nameMissing = ref(false);
const busy = ref(false);
const canApply = computed(() => session.can('scenarios:write'));
// Creating the resources needs the permissions to write both of them, besides the one of the scenario.
const canCreate = computed(() => session.can('honeytokens:write') && session.can('honeypots:write'));

const engageNames = useEngageNames();

const name = ref('');
const notes = ref('');
// Off at first: the guide says what to create, and creating it for them is the user's choice.
const createResources = ref(false);

function show(failure: unknown): string {
  return errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
}

// A change of the language asks again; the answer of the last question is the one that counts.
let asked = 0;

async function load(): Promise<void> {
  const mine = ++asked;
  loadError.value = undefined;
  try {
    const previous = deception.value;
    const body = (await api.call('getCatalogDeception', { path: { id: id.value }, query: { lang: locale.value } })).body;
    if (mine !== asked) {
      return;
    }
    deception.value = body;
    if (previous === undefined || name.value === previous.title) {
      name.value = body.title;
    }
  } catch (failure) {
    if (mine !== asked) {
      return;
    }
    if (failure instanceof ApiError && failure.kind === 'not_found') {
      missing.value = true;
    } else {
      loadError.value = show(failure);
    }
  } finally {
    if (mine === asked) {
      loading.value = false;
    }
  }
}

async function apply(): Promise<void> {
  error.value = undefined;
  // A name of spaces passes the required field, and the server would refuse it without saying which field.
  nameMissing.value = name.value.trim() === '';
  if (nameMissing.value || deception.value === undefined) {
    return;
  }
  busy.value = true;
  try {
    const { body } = await api.call('applyCatalogDeception', {
      path: { id: id.value },
      body: {
        name: name.value.trim(),
        notes: notes.value,
        language: locale.value,
        create_resources: canCreate.value && createResources.value,
      },
    });
    await router.replace({ name: 'scenario', params: { id: body.scenario.id } });
  } catch (failure) {
    error.value = show(failure);
  } finally {
    busy.value = false;
  }
}

onMounted(load);
watch(locale, load);
</script>

<template>
  <section>
    <p><RouterLink :to="{ name: 'catalog' }">{{ t('catalog.back') }}</RouterLink></p>

    <p v-if="loading" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="missing" class="notice" role="status">{{ t('error.not_found') }}</p>

    <template v-else-if="deception">
      <p v-if="loadError" class="notice notice-error" role="alert">{{ loadError }}</p>
      <div class="page-head">
        <div>
          <h1>{{ deception.title }}</h1>
          <p class="lede">{{ deception.summary }}</p>
          <p class="badges"><span class="badge">{{ t(`category.${deception.category}`) }}</span></p>
        </div>
      </div>

      <div class="section panel">
        <dl class="definition">
          <dt>{{ t('catalog.techniques') }}</dt>
          <dd class="mono">{{ deception.techniques.join(', ') }}</dd>
          <dt>{{ t('catalog.engage') }}</dt>
          <dd><bdi>{{ deception.engage_activities.map((activity) => engageLabel(activity, engageNames)).join(', ') }}</bdi></dd>
        </dl>
      </div>

      <div class="section panel">
        <DeceptionDetail :deception="deception" />
      </div>

      <div v-if="canApply" class="section panel narrow">
        <h2>{{ t('catalog.apply.title') }}</h2>
        <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>
        <form class="stack" novalidate @submit.prevent="apply">
          <div class="field">
            <label for="name">{{ t('field.name') }}</label>
            <input id="name" v-model="name" type="text" required maxlength="100" :aria-describedby="nameMissing ? 'name-problem' : undefined" />
            <span v-if="nameMissing" id="name-problem" class="hint problem" role="alert">{{ t('field.nameRequired') }}</span>
          </div>
          <div class="field">
            <label for="notes">{{ t('field.notes') }}</label>
            <textarea id="notes" v-model="notes" maxlength="2000"></textarea>
          </div>
          <div v-if="canCreate && (deception.honeytokens.length > 0 || deception.honeypots.length > 0)" class="field">
            <label class="check"><input id="create-resources" v-model="createResources" type="checkbox" />{{ t('catalog.apply.createResources') }}</label>
            <span class="hint">{{ t('catalog.apply.createResourcesHint', { list: t('catalog.slots') }) }}</span>
          </div>

          <div class="actions-row">
            <button class="button button-primary" type="submit" :disabled="busy">{{ busy ? t('app.saving') : t('catalog.apply.submit') }}</button>
          </div>
        </form>
      </div>
    </template>

    <p v-else-if="loadError" class="notice notice-error" role="alert">{{ loadError }}</p>
  </section>
</template>

<style scoped>
.badges {
  margin-top: 0.5rem;
}

.hint {
  color: var(--slate);
  font-size: 0.8125rem;
}

.problem {
  color: var(--danger);
}

.narrow {
  max-width: 36rem;
}

.check {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}
</style>
