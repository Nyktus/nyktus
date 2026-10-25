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
  /** The other pages of the same section, such as the detail page of a list, which keep the item marked as the current one. */
  pages?: readonly string[];
}

/** The pages of the frame. A page is added here when it exists. */
export const navigation: readonly NavItem[] = [
  { to: { name: 'home' }, label: 'nav.overview', group: 'detect' },
  { to: { name: 'incidents' }, label: 'nav.incidents', group: 'detect', permission: 'incidents:read', pages: ['incident', 'event'] },
  { to: { name: 'honeytokens' }, label: 'nav.honeytokens', group: 'inventory', permission: 'honeytokens:read', pages: ['honeytoken-new', 'honeytoken'] },
  { to: { name: 'honeypots' }, label: 'nav.honeypots', group: 'inventory', permission: 'honeypots:read', pages: ['honeypot-new', 'honeypot'] },
  { to: { name: 'scenarios' }, label: 'nav.scenarios', group: 'inventory', permission: 'scenarios:read', pages: ['scenario-new', 'scenario', 'scenario-add-deception', 'scenario-add-artifact'] },
  { to: { name: 'artifacts' }, label: 'nav.artifacts', group: 'inventory', permission: 'artifacts:read', pages: ['artifact'] },
  { to: { name: 'catalog' }, label: 'nav.catalog', group: 'inventory', permission: 'catalog:read', pages: ['catalog-artifacts', 'catalog-artifact', 'catalog-deception'] },
  { to: { name: 'alert-channels' }, label: 'nav.alertChannels', group: 'admin', permission: 'alert_channels:read', pages: ['alert-channel-new', 'alert-channel'] },
  { to: { name: 'users' }, label: 'nav.users', group: 'admin', permission: 'users:read', pages: ['user-new', 'user'] },
  { to: { name: 'api-keys' }, label: 'nav.apiKeys', group: 'admin', permission: 'api_keys:read', pages: ['api-key-new'] },
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

/** Tells whether the route is the page of the item or one of its section, so that a detail page keeps its list marked. */
export function isCurrent(item: NavItem, routeName: string | symbol | null | undefined): boolean {
  if (typeof routeName !== 'string') {
    return false;
  }
  const own = (item.to as { name?: unknown }).name;
  return own === routeName || (item.pages?.includes(routeName) ?? false);
}
