// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createApp } from 'vue';
import type { RouterHistory } from 'vue-router';
import App from './App.vue';
import { locale } from './i18n';
import { createConsoleRouter } from './router';
import { session } from './session';
import { captureFragmentToken } from './session/fragment';

/**
 * Returns the console, not yet mounted. The token of a link is taken out of the
 * address first: the router, which reads the address when it is created, must
 * never see it.
 */
export function createConsole(history?: RouterHistory) {
  captureFragmentToken(globalThis.location, globalThis.history);
  document.documentElement.lang = locale.value;
  const router = createConsoleRouter(session, history);
  return { app: createApp(App).use(router), router, root: App };
}
