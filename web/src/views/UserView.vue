<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { api } from '../api/client';
import { ApiError } from '../api/errors';
import type { OperationTypes, User } from '../api/generated';
import { errorText } from '../api/messages';
import ConfirmDialog from '../components/ConfirmDialog.vue';
import ConfirmWithPassword from '../components/ConfirmWithPassword.vue';
import LinkReveal from '../components/LinkReveal.vue';
import UserStatusBadge from '../components/UserStatusBadge.vue';
import { t } from '../i18n';
import { session } from '../session';

type Update = OperationTypes['updateUser']['body'];

const roles = ['admin', 'user', 'viewer'] as const;

const route = useRoute();
const router = useRouter();

const id = computed(() => String(route.params.id));
const user = ref<User | undefined>();
const loading = ref(true);
const missing = ref(false);
const error = ref<string | undefined>();
const saved = ref(false);
const busy = ref(false);

const displayName = ref('');
const role = ref<User['role']>('viewer');
const status = ref<User['status']>('active');

const canWrite = computed(() => session.can('users:write'));
const own = computed(() => user.value !== undefined && user.value.id === session.state.session?.user.id);
const oidc = computed(() => user.value?.sign_in_method === 'oidc');

/** The change that waits for the user to confirm that it ends the sessions of the account. */
const confirming = ref<Update | undefined>();
const removingFactor = ref(false);
const deleting = ref(false);

// A link that the server shows once. It lives here and goes when the user is done,
// asks for another, or leaves the page, which ends the component and its state.
const once = ref<{ kind: 'activation' | 'reset'; url: string; expires_at: string } | undefined>();

function show(failure: unknown): string {
  return errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
}

function adopt(from: User): void {
  user.value = from;
  displayName.value = from.display_name;
  role.value = from.role;
  status.value = from.status;
}

async function load(): Promise<void> {
  try {
    adopt((await api.call('getUser', { path: { id: id.value } })).body);
  } catch (failure) {
    if (failure instanceof ApiError && failure.kind === 'not_found') {
      missing.value = true;
    } else {
      error.value = show(failure);
    }
  } finally {
    loading.value = false;
  }
}

async function update(body: Update): Promise<void> {
  busy.value = true;
  try {
    adopt((await api.call('updateUser', { path: { id: id.value }, body })).body);
    // A change of the status can end the link that is shown, which the server removes with it.
    once.value = undefined;
    saved.value = true;
  } catch (failure) {
    error.value = show(failure);
    // The form shows what the server holds, not the change that it refused.
    if (user.value !== undefined) {
      adopt(user.value);
    }
  } finally {
    busy.value = false;
    confirming.value = undefined;
  }
}

function save(): void {
  const current = user.value;
  error.value = undefined;
  saved.value = false;
  if (current === undefined) {
    return;
  }
  // A name of spaces passes the required field, and the server would refuse it without saying which field.
  if (displayName.value.trim() === '') {
    error.value = t('field.nameRequired');
    return;
  }
  // Members that are left out stay as they are, so only what the user changed is sent.
  const body: Update = {};
  if (displayName.value.trim() !== current.display_name) {
    body.display_name = displayName.value.trim();
  }
  if (role.value !== current.role) {
    body.role = role.value;
  }
  // `pending` is shown, never chosen: the option is disabled, and the type says so.
  if (status.value !== current.status && status.value !== 'pending') {
    body.status = status.value;
  }
  if (Object.keys(body).length === 0) {
    saved.value = true;
  } else if (body.role !== undefined || body.status !== undefined) {
    // A new role or status ends every session of the account, which the user confirms.
    confirming.value = body;
  } else {
    void update(body);
  }
}

async function issue(kind: 'activation' | 'reset'): Promise<void> {
  error.value = undefined;
  saved.value = false;
  once.value = undefined;
  busy.value = true;
  try {
    const { body } = kind === 'activation' ? await api.call('createActivationLink', { path: { id: id.value } }) : await api.call('createPasswordResetLink', { path: { id: id.value } });
    once.value = { kind, url: body.url, expires_at: body.expires_at };
  } catch (failure) {
    error.value = show(failure);
  } finally {
    busy.value = false;
  }
}

/** Removes the second factor, confirmed with the password of the administrator. */
async function removeFactor(password: string | undefined): Promise<void> {
  adopt((await api.call('updateUser', { path: { id: id.value }, body: { totp_enabled: false, password } })).body);
}

function askFactor(): void {
  error.value = undefined;
  saved.value = false;
  removingFactor.value = true;
}

function factorRemoved(): void {
  removingFactor.value = false;
  saved.value = true;
}

function factorRefused(failure: ApiError): void {
  removingFactor.value = false;
  saved.value = false;
  error.value = errorText(failure);
}

async function remove(): Promise<void> {
  busy.value = true;
  try {
    await api.call('deleteUser', { path: { id: id.value } });
    await router.replace({ name: 'users' });
  } catch (failure) {
    deleting.value = false;
    error.value = show(failure);
  } finally {
    busy.value = false;
  }
}

onMounted(load);
</script>

<template>
  <section>
    <p><RouterLink :to="{ name: 'users' }">{{ t('users.back') }}</RouterLink></p>

    <p v-if="loading" role="status">{{ t('app.loading') }}</p>
    <p v-else-if="missing" class="notice" role="status">{{ t('error.not_found') }}</p>

    <template v-else-if="user">
      <div class="page-head">
        <div>
          <h1><bdi>{{ user.display_name }}</bdi></h1>
          <p class="badges">
            <UserStatusBadge :status="user.status" />
            <span class="badge">{{ t(`role.${user.role}`) }}</span>
            <span class="badge">{{ t(`signInMethod.${user.sign_in_method}`) }}</span>
          </p>
        </div>
      </div>

      <p v-if="own" class="notice" role="status">
        {{ t('users.own') }} <RouterLink to="/account">{{ t('users.ownLink') }}</RouterLink>
      </p>
      <p v-if="saved" class="notice notice-ok" role="status">{{ t('common.saved') }}</p>
      <p v-if="error" class="notice notice-error" role="alert">{{ error }}</p>

      <LinkReveal v-if="once" :kind="once.kind" :url="once.url" :expires-at="once.expires_at" @done="once = undefined" />

      <div class="section panel">
        <dl class="definition">
          <dt>{{ t('field.email') }}</dt>
          <dd><bdi>{{ user.email }}</bdi></dd>
          <dt>{{ t('users.secondFactor') }}</dt>
          <dd>{{ oidc ? t('users.factorProvider') : user.totp_enabled ? t('users.factorOn') : t('users.totpOff') }}</dd>
        </dl>
      </div>

      <div v-if="canWrite" class="section panel narrow">
        <h2>{{ t('users.change') }}</h2>
        <form class="stack" @submit.prevent="save">
          <div class="field">
            <label for="display-name">{{ t('field.displayName') }}</label>
            <input id="display-name" v-model="displayName" type="text" required maxlength="100" autocomplete="off" />
          </div>
          <div class="field">
            <label for="role">{{ t('users.role') }}</label>
            <select id="role" v-model="role" :disabled="own || oidc" aria-describedby="role-hint">
              <option v-for="option in roles" :key="option" :value="option">{{ t(`role.${option}`) }}</option>
            </select>
            <span id="role-hint" class="hint">{{ oidc ? t('users.roleProvider') : own ? t('users.ownLocked') : t('users.roleHint') }}</span>
          </div>
          <div class="field">
            <label for="status">{{ t('field.status') }}</label>
            <select id="status" v-model="status" :disabled="own" aria-describedby="status-hint">
              <option v-if="user.status === 'pending'" value="pending" disabled>{{ t('userStatus.pending') }}</option>
              <option value="active">{{ t('userStatus.active') }}</option>
              <option value="deactivated">{{ t('userStatus.deactivated') }}</option>
            </select>
            <span id="status-hint" class="hint">{{ own ? t('users.ownLocked') : t('users.statusHint') }}</span>
          </div>
          <div class="actions-row">
            <button class="button button-primary" type="submit" :disabled="busy">{{ busy ? t('app.saving') : t('common.save') }}</button>
          </div>
        </form>
      </div>

      <div v-if="canWrite" class="section panel narrow">
        <h2>{{ t('users.access') }}</h2>
        <div class="stack">
          <div v-if="user.status === 'pending'">
            <p class="hint">{{ t('users.activation.hint') }}</p>
            <button class="button button-ghost" type="button" :disabled="busy" @click="issue('activation')">{{ t('users.activation.new') }}</button>
          </div>
          <div v-if="user.status === 'active' && !oidc">
            <button class="button button-ghost" type="button" :disabled="busy" @click="issue('reset')">{{ t('users.reset.new') }}</button>
          </div>
          <div v-if="user.totp_enabled && !own">
            <p class="hint">{{ t('users.factor.hint') }}</p>
            <button class="button button-ghost" type="button" :disabled="busy" @click="askFactor">{{ t('users.factor.remove') }}</button>
          </div>
          <p v-if="!(user.status === 'pending' || (user.status === 'active' && !oidc) || (user.totp_enabled && !own))" class="hint">{{ t('users.accessNone') }}</p>
        </div>
      </div>

      <div v-if="canWrite" class="section panel narrow">
        <h2>{{ t('common.delete') }}</h2>
        <p class="hint">{{ own ? t('users.ownLocked') : t('users.delete.hint') }}</p>
        <div class="actions-row">
          <button class="button button-ghost" type="button" :disabled="own || busy" @click="deleting = true">{{ t('users.delete.confirm') }}</button>
        </div>
      </div>

      <ConfirmDialog
        v-if="canWrite"
        :open="confirming !== undefined"
        :title="t('users.sessions.title')"
        :confirm="t('common.save')"
        :busy="busy"
        neutral
        @confirm="confirming && update(confirming)"
        @cancel="confirming = undefined"
      >
        {{ t('users.sessions.body') }}
      </ConfirmDialog>

      <ConfirmWithPassword
        v-if="canWrite"
        :open="removingFactor"
        :title="t('users.factor.title')"
        :confirm="t('users.factor.remove')"
        :action="removeFactor"
        @done="factorRemoved"
        @cancel="removingFactor = false"
        @failed="factorRefused"
      />

      <ConfirmDialog
        v-if="canWrite"
        :open="deleting"
        :title="t('users.delete.title')"
        :confirm="t('users.delete.confirm')"
        :busy="busy"
        @confirm="remove"
        @cancel="deleting = false"
      >
        {{ t('users.delete.body') }}
      </ConfirmDialog>
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

.narrow {
  max-width: 36rem;
}
</style>
