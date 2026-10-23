// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, test } from 'vitest';
import { keyScopeRequires, keyScopes } from './api/generated';
import { dependentsOf, deselect, requirementsOf, select } from './keyScopes';

describe('requirementsOf', () => {
  test('is empty for a scope that needs nothing', () => {
    expect(requirementsOf('honeytokens:read')).toEqual([]);
    expect(requirementsOf('audit:read')).toEqual([]);
  });

  test('names a scope that is required directly', () => {
    expect(requirementsOf('incidents:write')).toEqual(['incidents:read']);
  });

  test('follows a chain of requirements, in the order of the list', () => {
    expect(requirementsOf('scenarios:write')).toEqual(['honeytokens:read', 'scenarios:read']);
    expect(requirementsOf('artifacts:write')).toEqual(['artifacts:read', 'honeytokens:read']);
  });
});

describe('select', () => {
  test('adds the scope with what it requires, each once, in the order of the list', () => {
    expect(select([], 'scenarios:write')).toEqual(['honeytokens:read', 'scenarios:read', 'scenarios:write']);
    expect(select(['honeytokens:read'], 'artifacts:write')).toEqual(['artifacts:read', 'artifacts:write', 'honeytokens:read']);
  });

  test('changes nothing for a scope that is selected', () => {
    expect(select(['audit:read'], 'audit:read')).toEqual(['audit:read']);
  });
});

describe('dependentsOf', () => {
  test('finds the selected scopes that need a scope, also through another', () => {
    const selected = select([], 'scenarios:write');
    expect(dependentsOf(selected, 'honeytokens:read')).toEqual(['scenarios:read', 'scenarios:write']);
    expect(dependentsOf(selected, 'scenarios:read')).toEqual(['scenarios:write']);
    expect(dependentsOf(selected, 'scenarios:write')).toEqual([]);
  });

  test('ignores the scopes that are not selected', () => {
    expect(dependentsOf(['honeytokens:read'], 'honeytokens:read')).toEqual([]);
  });
});

describe('deselect', () => {
  test('removes a scope that nothing selected needs', () => {
    expect(deselect(['honeytokens:read', 'audit:read'], 'audit:read')).toEqual(['honeytokens:read']);
    expect(deselect(select([], 'scenarios:write'), 'scenarios:write')).toEqual(['honeytokens:read', 'scenarios:read']);
  });

  test('keeps a scope that a selected scope needs', () => {
    const selected = select([], 'incidents:write');
    expect(deselect(selected, 'incidents:read')).toEqual(['incidents:read', 'incidents:write']);
  });
});

test('the requirements of the server are scopes, and a scope never requires itself', () => {
  for (const [scope, required] of Object.entries(keyScopeRequires)) {
    expect(keyScopes as readonly string[]).toContain(scope);
    expect(keyScopes as readonly string[]).toContain(required);
    expect(required).not.toBe(scope);
  }
});
