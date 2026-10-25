// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { Artifact } from './api/generated';

/** A file bound to a honeytoken of its scenario is a lure carrier; one without a binding is pocket litter. */
export function carriesHoneytoken(file: Pick<Artifact, 'bindings'>): boolean {
  return Object.keys(file.bindings).length > 0;
}
