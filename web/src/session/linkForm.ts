// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ref } from 'vue';
import { ApiError } from '../api/errors';
import { errorText } from '../api/messages';
import { takeFragmentToken } from './fragment';

export type LinkState = 'form' | 'done' | 'invalid';

/**
 * The state of a page that a link of the server leads to, which a person uses once
 * with a token from the link: the setup, the activation and the reset of a password.
 *
 * The token is held here and nowhere else, and only until it is used up: the
 * server accepts it once, and answers an unknown, expired or used token with a
 * 404 that says nothing more. Whatever ends the use, a success or that 404, also
 * ends what the form holds, so that no password stays in the page.
 */
export function useLinkForm(send: (token: string) => Promise<void>, wipe: () => void) {
  let token = takeFragmentToken();
  const state = ref<LinkState>(token === undefined ? 'invalid' : 'form');
  const busy = ref(false);
  const error = ref<string | undefined>();

  function finish(next: LinkState): void {
    token = undefined;
    wipe();
    state.value = next;
  }

  /** Sends the form once the checks of the page found no problem, which is a text to show. */
  async function submit(problem: string | undefined): Promise<void> {
    if (busy.value) {
      return;
    }
    error.value = problem;
    if (problem !== undefined || token === undefined) {
      return;
    }
    busy.value = true;
    try {
      await send(token);
      finish('done');
    } catch (failure) {
      if (failure instanceof ApiError && failure.kind === 'not_found') {
        finish('invalid');
      } else {
        error.value = errorText(failure instanceof ApiError ? failure : new ApiError('server', 0));
      }
    } finally {
      busy.value = false;
    }
  }

  return { state, busy, error, submit };
}
