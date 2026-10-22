// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { Honeypot, Honeytoken, Scenario, Session } from '../api/generated';

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

export function sessionBody(role: 'admin' | 'user' | 'viewer' = 'admin', name = 'Ada Admin'): Session {
  return {
    user: {
      id: '8d1c0f0e-1111-4222-8333-944444444444',
      email: 'ada@example.com',
      display_name: name,
      role,
      status: 'active',
      totp_enabled: false,
      sign_in_method: 'password',
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
