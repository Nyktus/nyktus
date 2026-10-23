// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { isConsolePath } from './returnTo';

/** The path that a browser navigates to; the client never requests it. */
const reauthenticatePath = '/api/v1/oidc/reauthenticate';

/**
 * Returns the address to which the browser goes to sign in again at the identity
 * provider and then back to a page of the console. The page is a path with an
 * optional query and no fragment. Anything else is left out, because the server
 * would refuse it; the user then returns to the overview.
 */
export function reauthenticationAddress(returnTo: string): string {
  const path = returnTo.split('#')[0] ?? '';
  return isConsolePath(path) ? `${reauthenticatePath}?return_to=${encodeURIComponent(path)}` : reauthenticatePath;
}

/**
 * Tells whether the identity provider could not confirm the user, which it says by
 * a fragment on the page it returns to, and removes the fragment: it says no more
 * than that, and it does not belong in the history.
 */
export function takeReauthenticationFailure(
  location: Pick<Location, 'pathname' | 'search' | 'hash'>,
  history: Pick<History, 'replaceState' | 'state'>,
): boolean {
  if (location.hash !== '#error=reauthentication') {
    return false;
  }
  history.replaceState(history.state, '', location.pathname + location.search);
  return true;
}
