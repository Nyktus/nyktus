// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

const maxLength = 512;

/**
 * Reports whether path is a path of the console: one slash, then characters that
 * a path may hold, and neither a second slash nor a backslash after the first,
 * which browsers read as another host. After a sign-in the console only ever goes
 * to such a path, never to a URL.
 */
export function isConsolePath(path: string): boolean {
  return path.length <= maxLength && /^\/(?![/\\])[A-Za-z0-9\-._~!$&'()*+,;=:@%/?#[\]]*$/.test(path) && !path.includes('\\');
}

let remembered: string | undefined;

/**
 * Remembers where the user was going when the session was missing, in memory
 * only: the path is neither in the URL, which the history and the logs of a
 * proxy keep, nor in the storage of the browser. A reload forgets it.
 */
export function rememberReturnPath(path: string): void {
  remembered = isConsolePath(path) ? path : undefined;
}

/** Returns the remembered path once, if it is acceptable to the router. */
export function takeReturnPath(acceptable: (path: string) => boolean): string | undefined {
  const path = remembered;
  remembered = undefined;
  return path !== undefined && acceptable(path) ? path : undefined;
}
