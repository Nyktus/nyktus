// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

/** The pages that links of the server lead to, with the token in the fragment. */
const tokenPages = ['/setup', '/activate', '/reset-password'];

/** A token is 32 random bytes in base64url; the bounds are wide so that the length may change. */
const tokenForm = /^[A-Za-z0-9_-]{16,128}$/;

let captured: string | undefined;

/**
 * Takes the token out of the fragment of the address and removes the fragment,
 * before the router starts: the router would otherwise keep the fragment in the
 * route it holds and in the entry of the history. The token stays in memory
 * until the page that needs it takes it. A reload therefore loses it, and the
 * user opens the link again.
 *
 * The fragment never reaches a server, so the token stays out of the logs of the
 * console and of a proxy; removing it also keeps it out of the history of the
 * browser, of bookmarks and of what a user copies from the address bar.
 */
export function captureFragmentToken(
  location: Pick<Location, 'pathname' | 'search' | 'hash'>,
  history: Pick<History, 'replaceState' | 'state'>,
): void {
  captured = undefined;
  // The server and the router also serve /activate/, which a mail program or a proxy may produce.
  if (!tokenPages.includes(location.pathname.replace(/\/+$/, '')) || location.hash === '') {
    return;
  }
  const token = new URLSearchParams(location.hash.slice(1)).get('token');
  if (token !== null && tokenForm.test(token)) {
    captured = token;
  }
  history.replaceState(history.state, '', location.pathname + location.search);
}

/** Returns the token once; a second call finds nothing. */
export function takeFragmentToken(): string | undefined {
  const token = captured;
  captured = undefined;
  return token;
}
