// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { watch } from 'vue';
import { createRouter, createWebHistory, type Router, type RouteRecordRaw } from 'vue-router';
import type { PlainMessageKey } from './i18n';
import { rememberReturnPath, takeReturnPath } from './session/returnTo';
import type { SessionStore } from './session/store';

declare module 'vue-router' {
  interface RouteMeta {
    /** The page is for users who are not signed in, and has no frame. */
    public?: boolean;
    /** The title of the page, a text of the catalog. */
    title: PlainMessageKey;
  }
}

export const routes: RouteRecordRaw[] = [
  { path: '/', name: 'home', component: () => import('./views/HomeView.vue'), meta: { title: 'home.title' } },
  {
    path: '/sign-in',
    name: 'sign-in',
    component: () => import('./views/SignInView.vue'),
    meta: { public: true, title: 'signIn.title' },
  },
  {
    path: '/setup',
    name: 'setup',
    component: () => import('./views/SetupView.vue'),
    meta: { public: true, title: 'setup.title' },
  },
  {
    path: '/activate',
    name: 'activate',
    component: () => import('./views/ActivateView.vue'),
    meta: { public: true, title: 'activate.title' },
  },
  {
    path: '/reset-password',
    name: 'reset-password',
    component: () => import('./views/ResetPasswordView.vue'),
    meta: { public: true, title: 'reset.title' },
  },
  {
    path: '/:path(.*)*',
    name: 'not-found',
    component: () => import('./views/NotFoundView.vue'),
    meta: { title: 'notFound.title' },
  },
];

/**
 * Returns the router of the console. A page needs a session; without one the
 * user is sent to the sign-in page, and back to the page after signing in. The
 * check only decides what the page shows: the server decides what the user may do.
 */
export function createConsoleRouter(session: SessionStore, history = createWebHistory()): Router {
  const router = createRouter({ history, routes });

  /** A path the router knows a page for, so that a path nobody linked to is not a target. */
  const knowsPage = (path: string): boolean => router.resolve(path).name !== 'not-found';

  router.beforeEach(async (to) => {
    // The pages for a link of the server, such as the activation, need no session.
    if (to.meta.public && to.name !== 'sign-in') {
      return true;
    }
    await session.ensureLoaded();
    // A server that did not answer says nothing about the session: the page says so and asks again.
    if (session.state.status === 'unavailable') {
      return true;
    }
    const signedIn = session.state.status === 'signed-in';
    if (to.meta.public) {
      return signedIn && to.name === 'sign-in' ? (takeReturnPath(knowsPage) ?? { name: 'home' }) : true;
    }
    if (!signedIn) {
      rememberReturnPath(to.fullPath);
      return { name: 'sign-in' };
    }
    return true;
  });

  // The session can end while a page is open, such as by the idle timeout, which
  // the next request finds out.
  watch(
    () => session.state.status,
    (status) => {
      const current = router.currentRoute.value;
      if (status === 'signed-out' && current.matched.length > 0 && !current.meta.public) {
        // A user who signed out on purpose does not come back to the page they left.
        if (!session.state.leftOnPurpose) {
          rememberReturnPath(current.fullPath);
        }
        void router.replace({ name: 'sign-in' });
      }
    },
  );

  return router;
}

/** Goes where the user was going before the sign-in, or to the overview. */
export async function leaveSignIn(router: Router): Promise<void> {
  const path = takeReturnPath((p) => router.resolve(p).name !== 'not-found');
  await router.replace(path ?? { name: 'home' });
}
