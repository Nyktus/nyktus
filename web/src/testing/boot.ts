// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { mount } from '@vue/test-utils';
import { flushPromises } from '@vue/test-utils';
import { vi } from 'vitest';
import type { fakeServer } from './fakeServer';

/**
 * Starts the console against a fake server, at path, with modules of its own: the
 * session and the language are state of the module, so each test starts clean.
 */
export async function boot(server: ReturnType<typeof fakeServer>, path = '/', navigate = true) {
  vi.resetModules();
  vi.stubGlobal('fetch', server.fetch);
  localStorage.clear();
  // Vue and its test utilities are loaded again with the rest, so that one copy of
  // Vue renders what the modules of the console keep in reactive state.
  const [{ createConsoleRouter }, { session }, { default: App }, i18n, client, utils, { createMemoryHistory }] = await Promise.all([
    import('../router'),
    import('../session'),
    import('../App.vue'),
    import('../i18n'),
    import('../api/client'),
    import('@vue/test-utils'),
    import('vue-router'),
  ]);
  i18n.setLocale('en');
  const router = createConsoleRouter(session, createMemoryHistory());
  if (navigate) {
    await router.push(path);
    await router.isReady();
  }
  const wrapper = utils.mount(App, { global: { plugins: [router] }, attachTo: document.body });
  await flushPromises();
  return { wrapper, router, session, i18n, client };
}

export async function type(wrapper: ReturnType<typeof mount>, selector: string, value: string): Promise<void> {
  await wrapper.get(selector).setValue(value);
}

export async function submit(wrapper: ReturnType<typeof mount>): Promise<void> {
  await wrapper.get('form').trigger('submit');
  await flushPromises();
}

/** Waits until the router has arrived at the page, which loads its code first, and the page is drawn. */
export async function arrive(router: { currentRoute: { value: { name?: string | symbol | null | undefined } } }, name: string): Promise<void> {
  await vi.waitFor(() => {
    if (router.currentRoute.value.name !== name) {
      throw new Error(`the router is at ${String(router.currentRoute.value.name)}, not at ${name}`);
    }
  });
  await flushPromises();
}
