// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { keyScopeRequires, keyScopes, type KeyScope } from './api/generated';

/** Puts scopes in the order of the server's list, each once. */
function ordered(scopes: Iterable<KeyScope>): KeyScope[] {
  const set = new Set(scopes);
  return keyScopes.filter((scope) => set.has(scope));
}

/** Returns what a scope requires, directly or through other scopes. */
export function requirementsOf(scope: KeyScope): KeyScope[] {
  const found: KeyScope[] = [];
  for (let next = keyScopeRequires[scope]; next !== undefined && !found.includes(next); next = keyScopeRequires[next]) {
    found.push(next);
  }
  return ordered(found);
}

/** Returns the scopes of a selection that need a scope, directly or through other scopes. */
export function dependentsOf(selected: readonly KeyScope[], scope: KeyScope): KeyScope[] {
  return selected.filter((other) => requirementsOf(other).includes(scope));
}

/** Adds a scope to a selection, with the scopes that it requires. */
export function select(selected: readonly KeyScope[], scope: KeyScope): KeyScope[] {
  return ordered([...selected, scope, ...requirementsOf(scope)]);
}

/** Removes a scope from a selection, unless a scope that stays requires it. */
export function deselect(selected: readonly KeyScope[], scope: KeyScope): KeyScope[] {
  return dependentsOf(selected, scope).length > 0 ? ordered(selected) : ordered(selected.filter((other) => other !== scope));
}
