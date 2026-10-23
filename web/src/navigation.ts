// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { RouteLocationRaw } from 'vue-router';
import type { Permission } from './api/generated';
import type { PlainMessageKey } from './i18n';

export interface NavItem {
  to: RouteLocationRaw;
  label: PlainMessageKey;
  /** What the role needs to use the page. Without one, every signed-in user may. */
  permission?: Permission;
}

/** The pages of the frame. A page is added here when it exists. */
export const navigation: readonly NavItem[] = [
  { to: { name: 'home' }, label: 'nav.overview' },
  { to: { name: 'incidents' }, label: 'nav.incidents', permission: 'incidents:read' },
  { to: { name: 'honeytokens' }, label: 'nav.honeytokens', permission: 'honeytokens:read' },
  { to: { name: 'honeypots' }, label: 'nav.honeypots', permission: 'honeypots:read' },
  { to: { name: 'scenarios' }, label: 'nav.scenarios', permission: 'scenarios:read' },
  { to: { name: 'artifacts' }, label: 'nav.artifacts', permission: 'artifacts:read' },
  { to: { name: 'catalog' }, label: 'nav.catalog', permission: 'catalog:read' },
  { to: { name: 'alert-channels' }, label: 'nav.alertChannels', permission: 'alert_channels:read' },
  { to: { name: 'users' }, label: 'nav.users', permission: 'users:read' },
  { to: { name: 'api-keys' }, label: 'nav.apiKeys', permission: 'api_keys:read' },
  { to: { name: 'audit' }, label: 'nav.audit', permission: 'audit:read' },
  { to: { name: 'metrics' }, label: 'nav.metrics', permission: 'metrics:read' },
];

/** Returns the items that a user can use; the server still checks every request. */
export function visibleItems(items: readonly NavItem[], can: (permission: Permission) => boolean): NavItem[] {
  return items.filter((item) => item.permission === undefined || can(item.permission));
}
