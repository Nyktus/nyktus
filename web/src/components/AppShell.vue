<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, useId, useTemplateRef, watch } from 'vue';
import { useRoute } from 'vue-router';
import { ApiError } from '../api/errors';
import { errorText } from '../api/messages';
import { t } from '../i18n';
import { groupedItems, isCurrent, navigation } from '../navigation';
import { session } from '../session';
import markUrl from '../assets/mark.svg';

const groups = computed(() => groupedItems(navigation, (permission) => session.can(permission)));
// The pages of the work stand in the row; the administration is rarely needed and waits behind one entry.
const work = computed(() => groups.value.filter((entry) => entry.group !== 'admin'));
const admin = computed(() => groups.value.find((entry) => entry.group === 'admin'));
const route = useRoute();
const adminCurrent = computed(() => admin.value?.items.some((item) => isCurrent(item, route.name)) ?? false);

// On a narrow screen the pages are behind a button. A page that is opened closes it again.
const menuOpen = ref(false);
const adminOpen = ref(false);
const menuButton = useTemplateRef<HTMLButtonElement>('menu-button');
const adminButton = useTemplateRef<HTMLButtonElement>('admin-button');
const adminBox = useTemplateRef<HTMLElement>('admin-box');
const labels = useId();
const adminList = useId();
watch(
  () => route.fullPath,
  () => {
    menuOpen.value = false;
    adminOpen.value = false;
  },
);

// A link to the page that is open changes no path, so the menus close with the click as well.
function closeOnLink(event: MouseEvent): void {
  if ((event.target as Element).closest('a') !== null) {
    menuOpen.value = false;
    adminOpen.value = false;
  }
}

// Escape closes what is open, and the focus goes back to the button that opened it.
function escape(): void {
  if (adminOpen.value) {
    adminOpen.value = false;
    adminButton.value?.focus();
  } else if (menuOpen.value) {
    menuOpen.value = false;
    menuButton.value?.focus();
  }
}

// The list of the administration is no dialog: a click elsewhere, or the focus moving on, closes it.
function clickElsewhere(event: MouseEvent): void {
  if (adminOpen.value && !adminBox.value?.contains(event.target as Node)) {
    adminOpen.value = false;
  }
}

function focusLeaves(event: FocusEvent): void {
  const next = event.relatedTarget as Node | null;
  if (next !== null && !adminBox.value?.contains(next)) {
    adminOpen.value = false;
  }
}

onMounted(() => document.addEventListener('click', clickElsewhere));
onBeforeUnmount(() => document.removeEventListener('click', clickElsewhere));

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
</script>

<template>
  <a class="skip" href="#main">{{ t('app.skipToContent') }}</a>
  <header class="bar" @keydown.esc="escape">
    <div class="top">
      <div class="top-inner">
        <RouterLink class="brand" :to="{ name: 'home' }">
          <img :src="markUrl" alt="" width="28" height="28" />
          <span>Nyktus</span>
        </RouterLink>
        <button ref="menu-button" class="button button-ghost menu-button" type="button" :aria-expanded="menuOpen" aria-controls="main-nav" @click="menuOpen = !menuOpen">
          {{ t('menu.pages') }}
        </button>
        <div class="account" role="group" :aria-label="t('menu.label')">
          <RouterLink v-if="user" class="who" :to="{ name: 'account' }" :title="t('menu.account')">
            <bdi class="name">{{ user.display_name }}</bdi>
            <span class="role">{{ t(`role.${user.role}`) }}</span>
          </RouterLink>
          <button class="button button-ghost" type="button" @click="signOut">{{ t('menu.signOut') }}</button>
        </div>
      </div>
      <p v-if="failure" class="notice notice-error failure" role="alert">{{ failure }}</p>
    </div>
    <div class="tabs" :class="{ open: menuOpen }">
      <nav id="main-nav" :aria-label="t('nav.label')" @click="closeOnLink">
        <ul class="groups">
          <li v-for="entry in work" :key="entry.group" class="group" :class="`group-${entry.group}`">
            <span :id="`${labels}-${entry.group}`" class="group-label">{{ t(`nav.group.${entry.group}`) }}</span>
            <ul :aria-labelledby="`${labels}-${entry.group}`">
              <li v-for="item in entry.items" :key="item.label">
                <RouterLink :to="item.to" :class="{ current: isCurrent(item, route.name) }">{{ t(item.label) }}</RouterLink>
              </li>
            </ul>
          </li>
          <li v-if="admin" ref="admin-box" class="group group-admin" @focusout="focusLeaves">
            <span :id="`${labels}-admin`" class="group-label">{{ t('nav.group.admin') }}</span>
            <button
              ref="admin-button"
              class="admin-button"
              :class="{ current: adminCurrent }"
              type="button"
              :aria-expanded="adminOpen"
              :aria-controls="adminList"
              @click.stop="adminOpen = !adminOpen"
            >
              {{ t('nav.group.admin') }}
              <svg class="chevron" viewBox="0 0 12 12" width="12" height="12" aria-hidden="true" focusable="false">
                <path d="M2.5 4.5 6 8l3.5-3.5" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" />
              </svg>
            </button>
            <ul :id="adminList" :class="{ open: adminOpen }" :aria-labelledby="`${labels}-admin`">
              <li v-for="item in admin.items" :key="item.label">
                <RouterLink :to="item.to" :class="{ current: isCurrent(item, route.name) }">{{ t(item.label) }}</RouterLink>
              </li>
            </ul>
          </li>
        </ul>
      </nav>
    </div>
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

/* Two layers: the account on the ground of the page, the pages on a lighter band of their own. */
.bar {
  position: relative;
  z-index: 5;
  border-bottom: 1px solid var(--line);
  background: var(--silver);
}

.top-inner,
.tabs nav {
  max-width: var(--measure);
  margin: 0 auto;
  padding-left: var(--gutter);
  padding-right: var(--gutter);
}

.top-inner {
  display: flex;
  align-items: center;
  gap: 1rem;
  min-height: var(--nav-height);
  padding-top: 0.5rem;
  padding-bottom: 0.5rem;
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

.account {
  display: flex;
  align-items: center;
  gap: 0.9rem;
  flex-wrap: wrap;
  /* The account stays at the right edge of the bar. */
  margin-left: auto;
}

.who {
  display: grid;
  color: inherit;
  line-height: 1.2;
  text-align: right;
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

.menu-button {
  display: none;
}

.tabs {
  border-top: 1px solid var(--line-soft);
  background: var(--surface-raised);
}

.groups {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.25rem 0.5rem;
  margin: 0;
  padding: 0.3rem 0;
  list-style: none;
}

.group {
  display: flex;
  align-items: center;
}

.group ul {
  display: flex;
  gap: 0.15rem;
  margin: 0;
  padding: 0;
  list-style: none;
}

/* The groups are told apart by a rule and by their order; the names stay for assistive technology. */
.group-label {
  position: absolute;
  width: 1px;
  height: 1px;
  margin: -1px;
  overflow: hidden;
  clip-path: inset(50%);
  white-space: nowrap;
}

.group + .group {
  padding-left: 0.5rem;
  border-left: 1px solid var(--line);
}

.group + .group-admin {
  position: relative;
  margin-left: auto;
  padding-left: 0;
  border-left: 0;
}

.group-admin .group-label {
  display: none;
}

nav a,
.admin-button {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  min-height: 2.5rem;
  padding: 0.4rem 0.8rem;
  border: 0;
  border-radius: var(--radius-sm);
  background: transparent;
  color: var(--ink);
  font: inherit;
  font-size: 0.9rem;
  font-weight: 600;
  text-decoration: none;
  cursor: pointer;
}

nav a:hover,
.admin-button:hover {
  background: var(--silver);
  color: var(--ink);
}

/* The page that is open, or the list it belongs to, is the one filled with the signal color. */
nav a.current,
.admin-button.current {
  background: var(--mint-soft);
  font-weight: 700;
}

.chevron {
  transition: transform 150ms ease-out;
}

.admin-button[aria-expanded='true'] .chevron {
  transform: rotate(180deg);
}

@media (prefers-reduced-motion: reduce) {
  .chevron {
    transition: none;
  }
}

/* The list of the administration opens below its button and does not move the page. */
.group-admin ul {
  display: none;
  position: absolute;
  top: calc(100% + 0.25rem);
  right: 0;
  z-index: 10;
  flex-direction: column;
  min-width: 13rem;
  padding: 0.35rem;
  border: 1px solid var(--line);
  border-radius: var(--radius-md);
  background: var(--surface-raised);
  box-shadow: var(--shadow);
}

.group-admin ul.open {
  display: flex;
}

.group-admin ul a {
  display: flex;
  width: 100%;
}

@media (max-width: 60rem) {
  .menu-button {
    display: inline-flex;
    margin-left: auto;
  }

  .account {
    flex: 1 1 100%;
    justify-content: space-between;
    margin-left: 0;
  }

  .who {
    text-align: left;
  }

  .tabs {
    display: none;
  }

  .tabs.open {
    display: block;
  }

  .groups {
    flex-direction: column;
    align-items: stretch;
    gap: 0.75rem;
    padding: 0.75rem 0;
  }

  .group,
  .group + .group-admin {
    display: grid;
    gap: 0.25rem;
    margin-left: 0;
    padding-left: 0;
    border-left: 0;
  }

  .group + .group {
    padding-top: 0.75rem;
    border-top: 1px solid var(--line-soft);
  }

  .group-label,
  .group-admin .group-label {
    display: block;
    position: static;
    width: auto;
    height: auto;
    margin: 0;
    overflow: visible;
    clip-path: none;
    color: var(--slate);
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }

  .admin-button {
    display: none;
  }

  .group ul,
  .group-admin ul,
  .group-admin ul.open {
    position: static;
    display: flex;
    flex-direction: column;
    min-width: 0;
    padding: 0;
    border: 0;
    border-radius: 0;
    background: transparent;
    box-shadow: none;
  }

  nav a {
    display: flex;
    width: 100%;
  }
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
