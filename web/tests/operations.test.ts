// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, test } from 'vitest';
import { operations } from '../src/api/generated';

const src = join(import.meta.dirname, '..', 'src');

/**
 * The operations that no page of the console uses yet. A page that starts to use one
 * removes it from the list, and the list can only shrink: an operation that is used
 * and still listed fails, as does one that is neither used nor listed.
 */
const pending = [
  'beginTOTPSetup',
  'changePassword',
  'completeOIDCSignIn',
  'confirmTOTP',
  'createAPIKey',
  'createActivationLink',
  'createPasswordResetLink',
  'createUser',
  'deleteUser',
  'getLiveness',
  'getMetrics',
  'getReadiness',
  'getUser',
  'listAPIKeys',
  'listAuditEntries',
  'listUsers',
  'removeTOTP',
  'replaceRecoveryCodes',
  'revokeAPIKey',
  'updateUser',
] as const;

function sources(): string {
  const parts: string[] = [];
  for (const name of readdirSync(src, { recursive: true, encoding: 'utf8' })) {
    if (/\.(ts|vue)$/.test(name) && !name.endsWith('.test.ts') && !name.startsWith('testing/') && !name.endsWith('generated.ts')) {
      parts.push(readFileSync(join(src, name), 'utf8'));
    }
  }
  return parts.join('\n');
}

test('every operation of the API is used by the console or listed as not yet used', () => {
  const text = sources();
  const used = new Set<string>();
  for (const [id, info] of Object.entries(operations)) {
    // A request goes through the client by its name; a navigation is a link to its path,
    // which the page takes from the table of the operations.
    const found = info.navigation ? text.includes(info.path) || text.includes(`operations.${id}`) : text.includes(`call('${id}'`);
    if (found) {
      used.add(id);
    }
  }
  const listed = new Set<string>(pending);
  expect([...listed].filter((id) => used.has(id)), 'used, but still listed as pending').toEqual([]);
  expect(
    Object.keys(operations).filter((id) => !used.has(id) && !listed.has(id)),
    'neither used nor listed as pending',
  ).toEqual([]);
  expect([...listed].filter((id) => !(id in operations)), 'listed, but not in the specification').toEqual([]);
  expect(pending).toEqual([...pending].sort());
});
