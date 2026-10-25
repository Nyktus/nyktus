// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { expect, test } from 'vitest';
import { carriesHoneytoken } from './artifactRole';

test('a file is a lure carrier when it is bound to a honeytoken, and pocket litter otherwise', () => {
  expect(carriesHoneytoken({ bindings: { portal: 'c0ffee00-aaaa-4222-8333-944444444444' } })).toBe(true);
  expect(carriesHoneytoken({ bindings: {} })).toBe(false);
});
