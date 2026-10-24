// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, test } from 'vitest';
import { rolePermissions, type Permission, type Role } from './api/generated';
import { groupedItems, isCurrent, navGroups, navigation, visibleItems, type NavItem } from './navigation';
import { operations } from './api/generated';
import { routes } from './router';

const items: NavItem[] = [
  { to: '/a', label: 'nav.overview', group: 'detect' },
  { to: '/b', label: 'nav.overview', group: 'inventory', permission: 'incidents:read' },
  { to: '/c', label: 'nav.overview', group: 'admin', permission: 'users:read' },
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

test('every page of the frame needs the permission that its route needs', () => {
  for (const item of navigation) {
    const to = item.to as { name: string };
    const route = routes.find((r) => r.name === to.name);
    expect(route, to.name).toBeDefined();
    expect(item.permission, to.name).toBe(route?.meta?.permission);
  }
});

test.each([
  ['incidents', 'incidents:read'],
  ['incident', 'incidents:read'],
  ['event', 'events:read'],
])('the page %s needs %s', (name, permission) => {
  expect(routes.find((r) => r.name === name)?.meta?.permission).toBe(permission);
});

describe('groupedItems', () => {
  test('puts the items of a user in the order of the groups, whatever the order of the list', () => {
    const shuffled: NavItem[] = [items[2]!, items[0]!, items[1]!];
    expect(groupedItems(shuffled, canAs('admin')).map((g) => [g.group, g.items.map((i) => i.to)])).toEqual([
      ['detect', ['/a']],
      ['inventory', ['/b']],
      ['admin', ['/c']],
    ]);
  });

  test('leaves out a group that has nothing for the role', () => {
    expect(groupedItems(items, canAs('viewer')).map((g) => g.group)).toEqual(['detect', 'inventory']);
    expect(groupedItems(items, () => false).map((g) => g.group)).toEqual(['detect']);
  });

  test('keeps the order of the items within a group', () => {
    const two: NavItem[] = [
      { to: '/x', label: 'nav.overview', group: 'detect' },
      { to: '/y', label: 'nav.overview', group: 'detect' },
    ];
    expect(groupedItems(two, () => true)[0]?.items.map((i) => i.to)).toEqual(['/x', '/y']);
  });
});

test('every page of the frame is in a group that is drawn, and a role sees only its own', () => {
  for (const item of navigation) {
    expect(navGroups).toContain(item.group);
  }
  const viewer = groupedItems(navigation, canAs('viewer')).flatMap((g) => g.items.map((i) => i.label));
  for (const label of ['nav.users', 'nav.apiKeys', 'nav.audit', 'nav.metrics', 'nav.alertChannels'] as const) {
    expect(viewer).not.toContain(label);
  }
  const admin = groupedItems(navigation, canAs('admin'));
  expect(admin.map((g) => g.group)).toEqual(['detect', 'inventory', 'admin']);
  expect(admin[2]?.items.map((i) => i.label)).toEqual(['nav.alertChannels', 'nav.users', 'nav.apiKeys', 'nav.audit', 'nav.metrics']);
});

// The permission that the console asks for a page is the one that the server asks for the request
// that the page is made of: a page that asked for less would show what the server then refuses,
// one that asked for more would hide what the user may use.
test.each([
  ['incidents', 'listIncidents'],
  ['incident', 'getIncident'],
  ['event', 'getEvent'],
  ['honeytokens', 'listHoneytokens'],
  ['honeytoken-new', 'createHoneytoken'],
  ['honeytoken', 'getHoneytoken'],
  ['honeypots', 'listHoneypots'],
  ['honeypot-new', 'createHoneypot'],
  ['honeypot', 'getHoneypot'],
  ['scenarios', 'listScenarios'],
  ['scenario-new', 'createScenario'],
  ['scenario', 'getScenario'],
  ['catalog', 'listCatalogDeceptions'],
  ['catalog-deception', 'getCatalogDeception'],
  ['artifacts', 'listArtifacts'],
  ['artifact', 'getArtifact'],
  ['alert-channels', 'listAlertChannels'],
  ['alert-channel-new', 'createAlertChannel'],
  ['alert-channel', 'getAlertChannel'],
  ['users', 'listUsers'],
  ['user-new', 'createUser'],
  ['user', 'getUser'],
  ['api-keys', 'listAPIKeys'],
  ['api-key-new', 'createAPIKey'],
  ['audit', 'listAuditEntries'],
  ['metrics', 'getMetrics'],
] as const)('the page %s asks for what the server asks for %s', (name, operation) => {
  expect(routes.find((r) => r.name === name)?.meta?.permission).toBe(operations[operation].access);
});

test('the pages that need no permission are the ones that every signed-in user may use, and the public ones', () => {
  const without = routes.filter((r) => r.meta?.permission === undefined).map((r) => String(r.name)).sort();
  expect(without).toEqual(['account', 'activate', 'forbidden', 'home', 'not-found', 'reset-password', 'setup', 'sign-in']);
  expect(operations.getSession.access).toBe('authenticated');
});

describe('isCurrent', () => {
  const item: NavItem = { to: { name: 'incidents' }, label: 'nav.incidents', group: 'detect', pages: ['incident', 'event'] };

  test('is true for the page of the item and for the pages of its section', () => {
    expect(isCurrent(item, 'incidents')).toBe(true);
    expect(isCurrent(item, 'incident')).toBe(true);
    expect(isCurrent(item, 'event')).toBe(true);
  });

  test('is false for any other page, and for a route without a name', () => {
    expect(isCurrent(item, 'honeytokens')).toBe(false);
    expect(isCurrent(item, 'honeytoken')).toBe(false);
    expect(isCurrent(item, undefined)).toBe(false);
    expect(isCurrent(item, null)).toBe(false);
    expect(isCurrent(item, Symbol('x'))).toBe(false);
  });

  test('is true only for the own page when the item has no section', () => {
    expect(isCurrent({ to: { name: 'home' }, label: 'nav.overview', group: 'detect' }, 'home')).toBe(true);
    expect(isCurrent({ to: { name: 'home' }, label: 'nav.overview', group: 'detect' }, 'incident')).toBe(false);
  });
});

// A page of the console that needs a permission is reached from the frame, so that it must keep one of its items marked.
// A page added to the router without its item would otherwise leave the frame with nothing marked.
test('every page that needs a permission belongs to exactly one item of the frame', () => {
  const owners = (name: string) => navigation.filter((item) => isCurrent(item, name)).map((item) => item.label);
  for (const route of routes) {
    if (typeof route.name === 'string' && route.meta?.permission !== undefined) {
      expect(owners(route.name), route.name).toHaveLength(1);
    }
  }
});

test('every page named as part of a section is a page of the router', () => {
  const names = new Set(routes.map((r) => r.name));
  for (const item of navigation) {
    for (const page of item.pages ?? []) {
      expect(names.has(page), page).toBe(true);
    }
  }
});
