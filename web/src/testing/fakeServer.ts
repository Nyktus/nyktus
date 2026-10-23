// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { Session } from '../api/generated';

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
