<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onMounted } from 'vue';
import { api } from '../api/client';
import type { User } from '../api/generated';
import DocsHint from '../components/DocsHint.vue';
import UserStatusBadge from '../components/UserStatusBadge.vue';
import { t } from '../i18n';
import { session } from '../session';
import { usePagedList } from '../usePagedList';

const list = usePagedList<User>(async (cursor) => {
  const { body } = await api.call('listUsers', { query: { limit: 50, cursor } });
  return { items: body.users, next: body.next_cursor };
});

const canWrite = computed(() => session.can('users:write'));

onMounted(list.reload);
</script>

<template>
  <section>
    <div class="page-head">
      <div>
        <h1>{{ t('users.title') }}</h1>
        <DocsHint />
      </div>
      <RouterLink v-if="canWrite" class="button button-primary" :to="{ name: 'user-new' }">{{ t('users.new') }}</RouterLink>
    </div>

    <p v-if="list.error.value" class="notice notice-error" role="alert">{{ t('users.loadFailed') }} {{ list.error.value }}</p>
    <p v-if="!list.loaded.value && list.loading.value" role="status">{{ t('app.loading') }}</p>
    <div v-else-if="list.items.value.length > 0" class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th scope="col">{{ t('field.name') }}</th>
            <th scope="col">{{ t('field.email') }}</th>
            <th scope="col">{{ t('users.role') }}</th>
            <th scope="col">{{ t('field.status') }}</th>
            <th scope="col">{{ t('users.signIn') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="user in list.items.value" :key="user.id">
            <td>
              <RouterLink :to="{ name: 'user', params: { id: user.id } }"><bdi>{{ user.display_name }}</bdi></RouterLink>
            </td>
            <td><bdi>{{ user.email }}</bdi></td>
            <td>{{ t(`role.${user.role}`) }}</td>
            <td><UserStatusBadge :status="user.status" /></td>
            <td>{{ t(`signInMethod.${user.sign_in_method}`) }}<template v-if="user.totp_enabled">, {{ t('users.totpOn') }}</template></td>
          </tr>
        </tbody>
      </table>
    </div>

    <p v-if="list.next.value !== undefined" class="actions-row more">
      <button class="button button-ghost" type="button" :disabled="list.loading.value" @click="list.more">{{ t('common.loadMore') }}</button>
    </p>
  </section>
</template>

<style scoped>
.more {
  margin-top: 1rem;
}
</style>
