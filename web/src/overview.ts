// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { Honeypot, Honeytoken, Incident } from './api/generated';

/**
 * How many entries of a list the overview asks for. The API does not count, so the
 * overview counts what one page holds, and a number that reaches the end of the page
 * is shown as a lower bound.
 */
export const pageLimit = 200;

/** What one page of a list held, and whether the list goes on beyond it. */
export interface Counted<T> {
  items: readonly T[];
  more: boolean;
}

/** A number as the overview shows it: exact, or with a plus sign when the list goes on beyond the page. */
export function countLabel(count: number, more: boolean, format: (n: number) => string = String): string {
  return more ? `${format(count)}+` : format(count);
}

const severityRank: Record<Incident['severity'], number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** How many incidents the overview lists. */
export const listedIncidents = 5;

export interface IncidentSummary {
  open: number;
  acknowledged: number;
  more: boolean;
  /** The incidents to look at first: open before acknowledged, the more severe first, the newer first. */
  lead: Incident[];
}

/** Reads the incidents that are not closed. Closed ones are not counted, whatever the list holds. */
export function summarizeIncidents(page: Counted<Incident>): IncidentSummary {
  const active = page.items.filter((incident) => incident.status !== 'closed');
  const rank = (incident: Incident): number => (incident.status === 'open' ? 100 : 0) + severityRank[incident.severity];
  // The list is newest first, and a stable sort keeps that order among equals.
  const lead = [...active].sort((a, b) => rank(b) - rank(a)).slice(0, listedIncidents);
  return {
    open: active.filter((incident) => incident.status === 'open').length,
    acknowledged: active.filter((incident) => incident.status === 'acknowledged').length,
    more: page.more,
    lead,
  };
}

export interface HoneypotSummary {
  online: number;
  offline: number;
  never: number;
  /** Disabled honeypots record nothing, so they are no fault when they are silent. */
  disabled: number;
  more: boolean;
  /** The enabled ones by service, in the order of the services, without a service that has none. */
  byService: { service: Honeypot['service']; count: number }[];
}

const honeypotServices: readonly Honeypot['service'][] = ['ssh', 'telnet', 'postgres', 'ldap', 'mcp'];

export function summarizeHoneypots(page: Counted<Honeypot>): HoneypotSummary {
  const enabled = page.items.filter((honeypot) => honeypot.enabled);
  return {
    online: enabled.filter((honeypot) => honeypot.status === 'online').length,
    offline: enabled.filter((honeypot) => honeypot.status === 'offline').length,
    never: enabled.filter((honeypot) => honeypot.status === 'never').length,
    disabled: page.items.length - enabled.length,
    more: page.more,
    byService: honeypotServices
      .map((service) => ({ service, count: enabled.filter((honeypot) => honeypot.service === service).length }))
      .filter((entry) => entry.count > 0),
  };
}

export interface HoneytokenSummary {
  active: number;
  /** A disabled honeytoken detects nothing. */
  disabled: number;
  more: boolean;
  /** The active ones by type, in the order of the types, without a type that has none. */
  byType: { type: Honeytoken['type']; count: number }[];
}

const honeytokenTypes: readonly Honeytoken['type'][] = ['web_url', 'web_image', 'dns'];

export function summarizeHoneytokens(page: Counted<Honeytoken>): HoneytokenSummary {
  const active = page.items.filter((honeytoken) => honeytoken.enabled);
  return {
    active: active.length,
    disabled: page.items.length - active.length,
    more: page.more,
    byType: honeytokenTypes
      .map((type) => ({ type, count: active.filter((honeytoken) => honeytoken.type === type).length }))
      .filter((entry) => entry.count > 0),
  };
}
