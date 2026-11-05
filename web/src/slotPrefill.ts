// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { LocationQuery } from 'vue-router';
import type { CatalogDeception } from './api/generated';
import { honeypotServices, honeytokenTypes, severities, type HoneypotService, type HoneytokenType, type Severity } from './resourceChoices';
import { parseTechniques } from './techniques';

/** What the address of a form of creation may fill in beforehand. Everything is a suggestion that the person can change. */
export interface Prefill {
  name?: string;
  severity?: Severity;
  techniques?: string[];
  type?: HoneytokenType;
  service?: HoneypotService;
}

type HoneytokenSlot = CatalogDeception['honeytokens'][number];
type HoneypotSlot = CatalogDeception['honeypots'][number];

// The longest name and the most techniques that the specification allows (`maxLength` of `name`, `maxItems` of `techniques`).
const nameLimit = 100;
const techniqueLimit = 20;

/** The query of the link that creates the honeytoken which a slot asks for. */
export function honeytokenSlotQuery(scenario: string, slot: HoneytokenSlot): Record<string, string> {
  const query: Record<string, string> = { scenario, type: slot.type, name: slot.label, severity: slot.severity };
  if (slot.techniques.length > 0) {
    query.techniques = slot.techniques.join(',');
  }
  return query;
}

/** The query of the link that creates the honeypot which a slot asks for. */
export function honeypotSlotQuery(scenario: string, slot: HoneypotSlot): Record<string, string> {
  return { scenario, service: slot.service, name: slot.label };
}

function single(query: LocationQuery, key: string): string | undefined {
  const value = query[key];
  return typeof value === 'string' ? value : undefined;
}

function oneOf<T extends string>(allowed: readonly T[], value: string | undefined): T | undefined {
  return allowed.find((candidate) => candidate === value);
}

// A name is text for an input field and never markup. One with a control or format character, or longer than the server
// takes, is not a name that a slot of the catalog gives, so it is dropped rather than shortened.
function nameOf(value: string | undefined): string | undefined {
  if (value === undefined || value.trim() === '' || value.length > nameLimit || /[\p{Cc}\p{Cf}]/u.test(value)) {
    return undefined;
  }
  return value;
}

function techniquesOf(value: string | undefined): string[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  // What is not an identifier is dropped; the form reads typed text the same way.
  const ids = parseTechniques(value).ids.slice(0, techniqueLimit);
  return ids.length > 0 ? ids : undefined;
}

function common(query: LocationQuery): Prefill {
  const found: Prefill = {};
  const name = nameOf(single(query, 'name'));
  if (name !== undefined) {
    found.name = name;
  }
  const severity = oneOf(severities, single(query, 'severity'));
  if (severity !== undefined) {
    found.severity = severity;
  }
  const techniques = techniquesOf(single(query, 'techniques'));
  if (techniques !== undefined) {
    found.techniques = techniques;
  }
  return found;
}

/** What the address of the form for honeytokens fills in: only values the form itself offers, nothing else. */
export function readHoneytokenPrefill(query: LocationQuery): Prefill {
  const found = common(query);
  const type = oneOf(honeytokenTypes, single(query, 'type'));
  if (type !== undefined) {
    found.type = type;
  }
  return found;
}

/** What the address of the form for honeypots fills in: only values the form itself offers, nothing else. */
export function readHoneypotPrefill(query: LocationQuery): Prefill {
  const found = common(query);
  const service = oneOf(honeypotServices, single(query, 'service'));
  if (service !== undefined) {
    found.service = service;
  }
  return found;
}
