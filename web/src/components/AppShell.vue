<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, ref } from 'vue';
import { ApiError } from '../api/errors';
import { errorText } from '../api/messages';
import { languageNames, locale, locales, setLocale, t, type Locale } from '../i18n';
import { navigation, visibleItems } from '../navigation';
import { session } from '../session';
import markUrl from '../assets/mark.svg';

const items = computed(() => visibleItems(navigation, (permission) => session.can(permission)));
const user = computed(() => session.state.session?.user);
const failure = ref<string | undefined>();

async function signOut(): Promise<void> {
  failure.value = undefined;
  try {
    // The router sends the user to the sign-in page once the session is gone.
    await session.signOut();
  } catch (error) {
    failure.value = errorText(error instanceof ApiError ? error : new ApiError('server', 0));
  }
}

function chooseLocale(event: Event): void {
  const value = (event.target as HTMLSelectElement).value;
  const chosen = locales.find((l) => l === value);
  if (chosen !== undefined) {
    setLocale(chosen);
  }
}
</script>

<template>
  <a class="skip" href="#main">{{ t('app.skipToContent') }}</a>
  <header class="bar">
    <div class="bar-inner">
      <RouterLink class="brand" :to="{ name: 'home' }">
        <img :src="markUrl" alt="" width="28" height="28" />
        <span>Nyktus</span>
      </RouterLink>
      <nav :aria-label="t('nav.label')">
        <ul>
          <li v-for="item in items" :key="item.label">
            <RouterLink :to="item.to">{{ t(item.label) }}</RouterLink>
          </li>
        </ul>
      </nav>
      <div class="account" role="group" :aria-label="t('menu.label')">
        <label class="visually-hidden" for="language">{{ t('menu.language') }}</label>
        <select id="language" :value="locale" @change="chooseLocale">
          <option v-for="l in locales" :key="l" :value="l" :lang="l">{{ languageNames[l as Locale] }}</option>
        </select>
        <span v-if="user" class="who">
          <bdi class="name">{{ user.display_name }}</bdi>
          <span class="role">{{ t(`role.${user.role}`) }}</span>
        </span>
        <button class="button button-ghost" type="button" @click="signOut">{{ t('menu.signOut') }}</button>
      </div>
    </div>
    <p v-if="failure" class="notice notice-error failure" role="alert">{{ failure }}</p>
  </header>
  <main id="main" tabindex="-1">
    <slot />
  </main>
</template>

<style scoped>
.skip {
  position: absolute;
  left: 0.5rem;
  top: -4rem;
  z-index: 10;
  padding: 0.5rem 0.9rem;
  border-radius: var(--radius-sm);
  background: var(--ink);
  color: var(--silver);
}

.skip:focus {
  top: 0.5rem;
}

.bar {
  border-bottom: 1px solid var(--line-soft);
  background: var(--silver);
}

.bar-inner {
  display: flex;
  align-items: center;
  gap: 1.5rem;
  max-width: var(--measure);
  min-height: var(--nav-height);
  margin: 0 auto;
  padding: 0.5rem var(--gutter);
  flex-wrap: wrap;
}

.brand {
  display: inline-flex;
  align-items: center;
  gap: 0.6rem;
  color: var(--ink);
  font-size: 1.3rem;
  font-weight: 800;
  letter-spacing: -0.03em;
  text-decoration: none;
}

nav {
  flex: 1;
}

nav ul {
  display: flex;
  gap: 1.25rem;
  margin: 0;
  padding: 0;
  list-style: none;
}

nav a {
  color: var(--ink);
  font-weight: 600;
  text-decoration: none;
}

nav a:hover {
  text-decoration: underline;
}

nav a.router-link-exact-active {
  text-decoration: underline;
  text-decoration-thickness: 2px;
}

.account {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  flex-wrap: wrap;
}

.account select {
  min-height: 2.25rem;
  padding: 0.25rem 0.5rem;
  border: 1px solid var(--field-border);
  border-radius: var(--radius-sm);
  background: var(--surface-raised);
  color: var(--ink);
  font: inherit;
}

.who {
  display: grid;
  line-height: 1.2;
}

.name {
  font-weight: 650;
}

.role {
  color: var(--slate);
  font-size: 0.8125rem;
}

.failure {
  max-width: var(--measure);
  margin: 0 auto 0.5rem;
}

main {
  max-width: var(--measure);
  margin: 0 auto;
  padding: 2rem var(--gutter) 4rem;
}

main:focus {
  outline: none;
}
</style>
