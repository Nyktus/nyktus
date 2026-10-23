// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { reactive, readonly } from 'vue';
import { ApiError } from '../api/errors';
import type { Client } from '../api/client';
import { rolePermissions, type Permission, type Session } from '../api/generated';

type Status = 'unknown' | 'signed-in' | 'signed-out' | 'unavailable';

interface State {
  status: Status;
  session: Session | undefined;
  /** The user signed out, as opposed to a session that ended, so that the page they left is not a target of the next sign-in. */
  leftOnPurpose: boolean;
}

export type SignInOutcome = { next: 'done' } | { next: 'second-factor' };

export type SecondFactorProof = { code: string } | { recovery_code: string };

/**
 * The state of the sign-in. It is a copy of what the server says about the
 * session, for showing the user's name and role, and never a credential: the
 * session itself is a cookie that scripts cannot read. A password is held only
 * while a request carries it, by the form that asked for it.
 */
export function createSessionStore(api: Pick<Client, 'call'>) {
  const state = reactive<State>({ status: 'unknown', session: undefined, leftOnPurpose: false });
  let loading: Promise<void> | undefined;

  function signedIn(session: Session): void {
    state.session = session;
    state.status = 'signed-in';
    state.leftOnPurpose = false;
  }

  function expire(onPurpose = false): void {
    state.session = undefined;
    state.status = 'signed-out';
    state.leftOnPurpose = onPurpose;
  }

  async function load(): Promise<void> {
    try {
      const { body } = await api.call('getSession', {});
      signedIn(body);
    } catch (error) {
      // Only the server's answer that there is no session sends the user to sign in:
      // a server that does not answer says nothing about the session.
      if (error instanceof ApiError && error.kind === 'unauthenticated') {
        expire();
        return;
      }
      state.session = undefined;
      state.status = 'unavailable';
    }
  }

  return {
    state: readonly(state),

    /**
     * Asks the server once whether there is a session; later calls wait for that
     * answer, except after a failure, which they ask again.
     */
    ensureLoaded(): Promise<void> {
      if (state.status === 'unavailable') {
        loading = undefined;
      }
      loading ??= load();
      return loading;
    },

    async signIn(email: string, password: string): Promise<SignInOutcome> {
      const result = await api.call('signIn', { body: { email, password } });
      if (result.status === 202) {
        return { next: 'second-factor' };
      }
      signedIn(result.body);
      return { next: 'done' };
    },

    async completeSecondFactor(proof: SecondFactorProof): Promise<void> {
      const { body } = await api.call('completeSignIn', { body: proof });
      signedIn(body);
    },

    async signOut(): Promise<void> {
      try {
        await api.call('signOut', {});
      } catch (error) {
        // A session that is already gone is what the user asked for.
        if (!(error instanceof ApiError && error.kind === 'unauthenticated')) {
          throw error;
        }
      }
      expire(true);
    },

    /** Records that the server no longer knows the session. */
    expire,

    /** Reports whether the role of the user grants a permission. The server decides; this only hides what is not usable. */
    can(permission: Permission): boolean {
      const role = state.session?.user.role;
      return role !== undefined && (rolePermissions[role] as readonly Permission[]).includes(permission);
    },
  };
}

export type SessionStore = ReturnType<typeof createSessionStore>;
