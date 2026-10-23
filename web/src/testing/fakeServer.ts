// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { AuditEntry, APIKey, CreatedAPIKey, User, AlertChannel, AlertDelivery, Artifact, CatalogDeception, CatalogDeceptionSummary, Event, Honeypot, Honeytoken, Incident, Scenario, Session } from '../api/generated';

export interface Recorded {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: unknown;
  credentials: RequestCredentials | undefined;
  redirect: RequestRedirect | undefined;
  cache: RequestCache | undefined;
  signal: AbortSignal | null | undefined;
}

export type Handler = (request: Recorded) => Response | Promise<Response>;

export function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
}

export function failure(status: number, code: string, headers: Record<string, string> = {}): Response {
  return json(status, { error: { code, message: 'message that the console must never show' } }, headers);
}

export const noContent = (): Response => new Response(null, { status: 204 });

export function sessionBody(role: 'admin' | 'user' | 'viewer' = 'admin', name = 'Ada Admin', method: 'password' | 'oidc' = 'password', totp = false): Session {
  return {
    user: {
      id: '8d1c0f0e-1111-4222-8333-944444444444',
      email: 'ada@example.com',
      display_name: name,
      role,
      status: 'active',
      totp_enabled: totp,
      sign_in_method: method,
    },
    idle_expires_at: '2026-10-22T20:00:00Z',
    expires_at: '2026-10-23T08:00:00Z',
  };
}

/**
 * A server for tests: it answers by method and path, such as 'GET /api/v1/session',
 * records every request and answers an unknown route with a 404, like the console.
 */
export function fakeServer(routes: Record<string, Handler>) {
  const requests: Recorded[] = [];
  const handlers = new Map(Object.entries(routes));
  return {
    requests,
    /** Replaces or adds the answer to a route. */
    on(route: string, handler: Handler): void {
      handlers.set(route, handler);
    },
    fetch: async (input: string, init: RequestInit): Promise<Response> => {
      const method = init.method ?? 'GET';
      const path = input.split('?')[0] ?? input;
      const headers = (init.headers ?? {}) as Record<string, string>;
      const body: unknown = typeof init.body === 'string' ? JSON.parse(init.body) : undefined;
      const recorded: Recorded = {
        method,
        url: input,
        headers,
        body,
        credentials: init.credentials,
        redirect: init.redirect,
        cache: init.cache,
        signal: init.signal,
      };
      requests.push(recorded);
      const handler = handlers.get(`${method} ${path}`);
      return handler ? handler(recorded) : failure(404, 'not_found');
    },
  };
}

const honeytokenId = 'c0ffee00-1111-4222-8333-944444444444';

export function honeytoken(overrides: Partial<Honeytoken> = {}): Honeytoken {
  return {
    id: honeytokenId,
    type: 'web_url',
    name: 'Backup share link',
    notes: 'In the old wiki.\nPage "Backups".',
    enabled: true,
    redirect_url: null,
    techniques: ['T1078'],
    severity: 'high',
    trigger_value: 'abcdefghijklmnopqrstuvwxyz',
    trigger_url: 'https://t.example.net/abcdefghijklmnopqrstuvwxyz',
    trigger_names: [],
    scenario_id: null,
    created_at: '2026-10-20T08:30:00Z',
    updated_at: '2026-10-21T09:00:00Z',
    ...overrides,
  };
}

export const honeypotId = 'beefbeef-1111-4222-8333-944444444444';
// Plainly made up, so that a scan for secrets does not take it for one.
export const honeypotSecret = `test-secret-${'x'.repeat(31)}`;
export const honeypotConfig = `- id: ${honeypotId}\n  service: ssh\n  listen: ":22"\n  secret: ${honeypotSecret}\n`;

export function honeypot(overrides: Partial<Honeypot> = {}): Honeypot {
  return {
    id: honeypotId,
    service: 'ssh',
    name: 'Jump host',
    notes: 'VLAN 20, rack 4',
    enabled: true,
    techniques: ['T1078'],
    severity: 'medium',
    scenario_id: null,
    status: 'online',
    last_seen_at: '2026-10-22T07:55:00Z',
    sensor_version: '0.1.0',
    created_at: '2026-10-20T08:30:00Z',
    updated_at: '2026-10-21T09:00:00Z',
    ...overrides,
  };
}

/** What the server answers when a secret is created or replaced. */
export function withSecret(h: Honeypot) {
  return { ...h, status: 'never' as const, last_seen_at: null, sensor_version: null, secret: honeypotSecret, sensor_config: honeypotConfig };
}

export const scenarioId = 'dec0de00-1111-4222-8333-944444444444';

export function scenario(overrides: Partial<Scenario> = {}): Scenario {
  return {
    id: scenarioId,
    name: 'Stolen backup',
    notes: 'A backup that someone left on a share.',
    engage_activities: ['EAC0005'],
    deception_id: null,
    language: null,
    persona: null,
    created_at: '2026-10-20T08:30:00Z',
    updated_at: '2026-10-21T09:00:00Z',
    ...overrides,
  };
}

export function catalogSummary(overrides: Partial<CatalogDeceptionSummary> = {}): CatalogDeceptionSummary {
  return {
    id: 'browser-bookmarks',
    category: 'data',
    title: 'Browser bookmarks',
    summary: 'An export of bookmarks with a link that leads to a honeytoken.',
    techniques: ['T1217'],
    engage_activities: ['EAC0005'],
    ...overrides,
  };
}

export function catalogDeception(overrides: Partial<CatalogDeception> = {}): CatalogDeception {
  return {
    ...catalogSummary(),
    honeytokens: [{ key: 'portal', type: 'web_url', label: 'Portal link', techniques: ['T1217'], severity: 'high' }],
    persona: [
      { key: 'company', kind: 'text', label: 'Company', example: 'Acme Corp' },
      { key: 'host', kind: 'host', label: 'Portal host', example: 'portal.acme.example' },
    ],
    secrets: [{ key: 'password', length: 16 }],
    artifacts: [{ key: 'bookmarks', file_name: 'bookmarks.html', format: 'html' }],
    ...overrides,
  };
}

export const artifactId = 'a11fac70-1111-4222-8333-944444444444';

export function artifact(overrides: Partial<Artifact> = {}): Artifact {
  return {
    id: artifactId,
    scenario_id: scenarioId,
    deception_artifact: 'bookmarks',
    file_name: 'bookmarks.html',
    format: 'html',
    media_type: 'text/html',
    size: 2048,
    placement_notes: 'On the share \\\\fs01\\it.',
    created_at: '2026-10-20T08:30:00Z',
    updated_at: '2026-10-21T09:00:00Z',
    ...overrides,
  };
}

export const incidentId = 'f00dfeed-1111-4222-8333-944444444444';

export function incident(overrides: Partial<Incident> = {}): Incident {
  return {
    id: incidentId,
    resource_type: 'scenario',
    resource_id: scenarioId,
    status: 'open',
    severity: 'high',
    event_severity: 'high',
    severity_override: null,
    techniques: ['T1078'],
    event_techniques: ['T1078'],
    techniques_override: null,
    notes: '',
    event_count: 2,
    first_event_at: '2026-10-22T07:00:00Z',
    last_event_at: '2026-10-22T07:05:00Z',
    opened_at: '2026-10-22T07:00:05Z',
    acknowledged_at: null,
    closed_at: null,
    ...overrides,
  };
}

export const eventId = 'e7e47000-1111-4222-8333-944444444444';

/** An event of a web honeytoken, which a client requested. */
export function event(overrides: Partial<Event> = {}): Event {
  return {
    id: eventId,
    resource_type: 'honeytoken',
    resource_id: honeytokenId,
    scenario_id: scenarioId,
    honeytoken_type: 'web_url',
    techniques: ['T1078'],
    severity: 'high',
    incident_id: incidentId,
    occurred_at: '2026-10-22T07:00:00Z',
    recorded_at: '2026-10-22T07:00:05Z',
    channel: 'http',
    client_ip: '203.0.113.7',
    http: { method: 'GET', user_agent: 'curl/8.4.0', referer: '', accept_language: 'en' },
    dns: null,
    sensor: null,
    ...overrides,
  };
}

/** An event of a honeypot: a session in which someone tried to log in. */
export function sensorEvent(overrides: Partial<Event> = {}): Event {
  return event({
    id: 'e7e47000-2222-4222-8333-944444444444',
    resource_type: 'honeypot',
    resource_id: honeypotId,
    honeytoken_type: null,
    channel: 'sensor',
    http: null,
    sensor: {
      service: 'ssh',
      event_type: 'login_attempt',
      port: 22,
      duration_ms: 4200,
      client_version: 'SSH-2.0-libssh_0.9',
      database: null,
      application_name: null,
      query: null,
      attempts: [
        { username: 'root', password_length: 8, key_fingerprint: null },
        { username: 'admin', password_length: null, key_fingerprint: 'SHA256:abc' },
      ],
    },
    ...overrides,
  });
}

/** An event of a DNS honeytoken. */
export function dnsEvent(overrides: Partial<Event> = {}): Event {
  return event({
    id: 'e7e47000-3333-4222-8333-944444444444',
    honeytoken_type: 'dns',
    channel: 'dns',
    http: null,
    dns: { zone: 't.example.net', prefix: 'abcdefghijklmnopqrstuvwxyz', qtype: 'A', transport: 'udp' },
    ...overrides,
  });
}

export const channelId = 'cafe0000-1111-4222-8333-944444444444';

export function alertChannel(overrides: Partial<AlertChannel> = {}): AlertChannel {
  return {
    id: channelId,
    name: 'SOAR',
    type: 'webhook',
    enabled: true,
    target: 'https://soar.example.com',
    header_name: 'Authorization',
    recipients: null,
    created_at: '2026-10-20T08:30:00Z',
    updated_at: '2026-10-21T09:00:00Z',
    ...overrides,
  };
}

export function emailChannel(overrides: Partial<AlertChannel> = {}): AlertChannel {
  return alertChannel({ id: 'cafe0000-2222-4222-8333-944444444444', name: 'SOC mailbox', type: 'email', target: null, header_name: null, recipients: ['soc@example.com', 'it@example.com'], ...overrides });
}

export const deliveryId = 'de11be00-1111-4222-8333-944444444444';

export function alertDelivery(overrides: Partial<AlertDelivery> = {}): AlertDelivery {
  return {
    id: deliveryId,
    incident_id: incidentId,
    channel_id: channelId,
    channel_type: 'webhook',
    channel_name: 'SOAR',
    status: 'delivered',
    attempts: 1,
    next_attempt_at: null,
    last_attempt_at: '2026-10-22T07:00:10Z',
    last_status_code: 200,
    last_error: null,
    last_duration_ms: 120,
    delivered_at: '2026-10-22T07:00:10Z',
    created_at: '2026-10-22T07:00:05Z',
    ...overrides,
  };
}

export const userId = 'a5e70000-1111-4222-8333-944444444444';

/** The account of another person than the one who is signed in. */
export function userRecord(overrides: Partial<User> = {}): User {
  return {
    id: userId,
    email: 'jane@example.com',
    display_name: 'Jane Doe',
    role: 'user',
    status: 'active',
    totp_enabled: false,
    sign_in_method: 'password',
    ...overrides,
  };
}

/** The account of the administrator who is signed in, as the session shows it. */
export function ownRecord(overrides: Partial<User> = {}): User {
  return userRecord({ id: '8d1c0f0e-1111-4222-8333-944444444444', email: 'ada@example.com', display_name: 'Ada Admin', role: 'admin', ...overrides });
}

export const keyId = 'ba5e0000-1111-4222-8333-944444444444';
// Plainly made up, so that a scan for secrets does not take it for a real key.
export const keySecret = `test-secret-key-${'x'.repeat(30)}`;

export function apiKey(overrides: Partial<APIKey> = {}): APIKey {
  return {
    id: keyId,
    name: 'SIEM export',
    created_by: '8d1c0f0e-1111-4222-8333-944444444444',
    scopes: ['audit:read'],
    created_at: '2026-10-20T08:30:00Z',
    expires_at: '2027-10-20T00:00:00Z',
    last_used_at: null,
    ...overrides,
  };
}

/** What the server answers when a key is created: the key itself, once. */
export function createdKey(overrides: Partial<CreatedAPIKey> = {}): CreatedAPIKey {
  return { ...apiKey(), last_used_at: null, key: keySecret, ...overrides };
}

export function auditEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    id: '0d17e000-1111-4222-8333-944444444444',
    occurred_at: '2026-10-23T09:00:00Z',
    action: 'honeytoken.update',
    outcome: 'success',
    actor: { kind: 'user', auth_method: 'session', user_id: '8d1c0f0e-1111-4222-8333-944444444444', email: 'ada@example.com', display_name: 'Ada Admin' },
    resource: { type: 'honeytoken', id: 'c0ffee00-1111-4222-8333-944444444444' },
    changed_fields: ['name', 'notes'],
    client_ip: '203.0.113.9',
    request_id: 'req-1234',
    ...overrides,
  };
}

/** The metrics as the server writes them, in the text format of Prometheus. */
export const metricsText = [
  '# HELP nyktus_event_jobs Jobs of events that wait to be processed.',
  '# TYPE nyktus_event_jobs gauge',
  'nyktus_event_jobs 3',
  '# HELP nyktus_incidents Incidents that are not closed.',
  '# TYPE nyktus_incidents gauge',
  'nyktus_incidents{status="open"} 2',
  'nyktus_incidents{status="acknowledged"} 1',
  '# HELP nyktus_periodic_task_last_success_timestamp_seconds When a periodic task last ran to its end.',
  '# TYPE nyktus_periodic_task_last_success_timestamp_seconds gauge',
  'nyktus_periodic_task_last_success_timestamp_seconds{task="delete_expired_sign_in_data"} 1792746000',
  '',
].join('\n');

export function plain(status: number, body: string): Response {
  return new Response(body, { status, headers: { 'Content-Type': 'text/plain; version=0.0.4' } });
}
