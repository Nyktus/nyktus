// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, test } from 'vitest';
import { rolePermissions, type Permission, type Role } from './api/generated';
import { navigation, visibleItems, type NavItem } from './navigation';

const items: NavItem[] = [
  { to: '/a', label: 'nav.overview' },
  { to: '/b', label: 'nav.overview', permission: 'incidents:read' },
  { to: '/c', label: 'nav.overview', permission: 'users:read' },
];

const canAs = (role: Role) => (permission: Permission) => (rolePermissions[role] as readonly Permission[]).includes(permission);

describe('visibleItems', () => {
  test('shows an administrator every page', () => {
    expect(visibleItems(items, canAs('admin')).map((i) => i.to)).toEqual(['/a', '/b', '/c']);
  });

  test('hides what a role cannot use', () => {
    expect(visibleItems(items, canAs('viewer')).map((i) => i.to)).toEqual(['/a', '/b']);
    expect(visibleItems(items, canAs('user')).map((i) => i.to)).toEqual(['/a', '/b']);
  });

  test('shows a page without a permission to everyone who is signed in', () => {
    expect(visibleItems(items, () => false).map((i) => i.to)).toEqual(['/a']);
  });
});

test('the frame links to the overview', () => {
  expect(navigation.map((i) => i.label)).toContain('nav.overview');
});
