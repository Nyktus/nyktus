<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, ref, useId, useTemplateRef, watch } from 'vue';
import { useRoute } from 'vue-router';
import { ApiError } from '../api/errors';
import { errorText } from '../api/messages';
import { languageNames, locale, locales, setLocale, t, type Locale } from '../i18n';
import { groupedItems, navigation } from '../navigation';
import { session } from '../session';
import markUrl from '../assets/mark.svg';

const groups = computed(() => groupedItems(navigation, (permission) => session.can(permission)));
const route = useRoute();
// On a narrow screen the pages are behind a button. A page that is opened closes it again.
const menuOpen = ref(false);
const menuButton = useTemplateRef<HTMLButtonElement>('menu-button');
const labels = useId();
watch(
  () => route.fullPath,
  () => {
    menuOpen.value = false;
  },
);

// A link to the page that is open changes no path, so the menu closes with the click as well.
// Escape closes it too, and the focus goes back to the button that opened it.
function closeMenu(): void {
  menuOpen.value = false;
}

function escape(): void {
  if (menuOpen.value) {
    menuOpen.value = false;
    menuButton.value?.focus();
  }
}
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
  <header class="bar" @keydown.esc="escape">
    <div class="bar-inner">
      <RouterLink class="brand" :to="{ name: 'home' }">
        <img :src="markUrl" alt="" width="28" height="28" />
        <span>Nyktus</span>
      </RouterLink>
      <button ref="menu-button" class="button button-ghost menu-button" type="button" :aria-expanded="menuOpen" aria-controls="main-nav" @click="menuOpen = !menuOpen">
        {{ t('menu.pages') }}
      </button>
      <nav id="main-nav" :aria-label="t('nav.label')" :class="{ open: menuOpen }" @click="closeMenu">
        <ul class="groups">
          <li v-for="entry in groups" :key="entry.group" class="group">
            <span :id="`${labels}-${entry.group}`" class="group-label">{{ t(`nav.group.${entry.group}`) }}</span>
            <ul :aria-labelledby="`${labels}-${entry.group}`">
              <li v-for="item in entry.items" :key="item.label">
                <RouterLink :to="item.to">{{ t(item.label) }}</RouterLink>
              </li>
            </ul>
          </li>
        </ul>
      </nav>
      <div class="account" role="group" :aria-label="t('menu.label')">
        <label class="visually-hidden" for="language">{{ t('menu.language') }}</label>
        <select id="language" :value="locale" @change="chooseLocale">
          <option v-for="l in locales" :key="l" :value="l" :lang="l">{{ languageNames[l as Locale] }}</option>
        </select>
        <RouterLink v-if="user" class="who" :to="{ name: 'account' }" :title="t('menu.account')">
          <bdi class="name">{{ user.display_name }}</bdi>
          <span class="role">{{ t(`role.${user.role}`) }}</span>
        </RouterLink>
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
  flex: 1 1 100%;
  order: 3;
}

.groups {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem 2rem;
  margin: 0;
  padding: 0;
  list-style: none;
}

.group {
  display: flex;
  flex-wrap: wrap;
  gap: 0.15rem 1rem;
  align-items: baseline;
}

.group-label {
  color: var(--slate);
  font-size: 0.75rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.group ul {
  display: flex;
  flex-wrap: wrap;
  gap: 0.15rem 1.1rem;
  margin: 0;
  padding: 0;
  list-style: none;
}

.menu-button {
  display: none;
}

@media (max-width: 52rem) {
  .menu-button {
    display: inline-flex;
    margin-left: auto;
  }

  nav {
    display: none;
  }

  nav.open {
    display: block;
  }

  .groups {
    flex-direction: column;
    gap: 0.75rem;
  }

  .group {
    display: grid;
    gap: 0.25rem;
  }

  .group ul {
    flex-direction: column;
    gap: 0.1rem;
  }

  nav a {
    display: block;
    padding: 0.35rem 0;
  }
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
  /* The account stays at the right edge of the bar while the pages stand in a row of their own below. */
  margin-left: auto;
}

@media (max-width: 52rem) {
  .account {
    margin-left: 0;
  }
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
  color: inherit;
  line-height: 1.2;
  text-decoration: none;
}

.who:hover .name,
.who:focus-visible .name {
  text-decoration: underline;
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
