// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { RouteLocationRaw } from 'vue-router';
import type { Permission } from './api/generated';
import type { PlainMessageKey } from './i18n';

/** The groups of the frame, in the order in which they are drawn. */
export const navGroups = ['detect', 'inventory', 'admin'] as const;

/** What a page is for: following what happens, the decoys, or running the installation. */
export type NavGroup = (typeof navGroups)[number];

export interface NavItem {
  to: RouteLocationRaw;
  label: PlainMessageKey;
  group: NavGroup;
  /** What the role needs to use the page. Without one, every signed-in user may. */
  permission?: Permission;
}

/** The pages of the frame. A page is added here when it exists. */
export const navigation: readonly NavItem[] = [
  { to: { name: 'home' }, label: 'nav.overview', group: 'detect' },
  { to: { name: 'incidents' }, label: 'nav.incidents', group: 'detect', permission: 'incidents:read' },
  { to: { name: 'honeytokens' }, label: 'nav.honeytokens', group: 'inventory', permission: 'honeytokens:read' },
  { to: { name: 'honeypots' }, label: 'nav.honeypots', group: 'inventory', permission: 'honeypots:read' },
  { to: { name: 'scenarios' }, label: 'nav.scenarios', group: 'inventory', permission: 'scenarios:read' },
  { to: { name: 'artifacts' }, label: 'nav.artifacts', group: 'inventory', permission: 'artifacts:read' },
  { to: { name: 'catalog' }, label: 'nav.catalog', group: 'inventory', permission: 'catalog:read' },
  { to: { name: 'alert-channels' }, label: 'nav.alertChannels', group: 'admin', permission: 'alert_channels:read' },
  { to: { name: 'users' }, label: 'nav.users', group: 'admin', permission: 'users:read' },
  { to: { name: 'api-keys' }, label: 'nav.apiKeys', group: 'admin', permission: 'api_keys:read' },
  { to: { name: 'audit' }, label: 'nav.audit', group: 'admin', permission: 'audit:read' },
  { to: { name: 'metrics' }, label: 'nav.metrics', group: 'admin', permission: 'metrics:read' },
];

/** Returns the items that a user can use; the server still checks every request. */
export function visibleItems(items: readonly NavItem[], can: (permission: Permission) => boolean): NavItem[] {
  return items.filter((item) => item.permission === undefined || can(item.permission));
}

/** Splits the items that a user can use into their groups, and leaves out a group that has none. */
export function groupedItems(items: readonly NavItem[], can: (permission: Permission) => boolean): { group: NavGroup; items: NavItem[] }[] {
  const usable = visibleItems(items, can);
  return navGroups.map((group) => ({ group, items: usable.filter((item) => item.group === group) })).filter((entry) => entry.items.length > 0);
}
