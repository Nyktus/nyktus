// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, test, vi } from 'vitest';
import { failure, fakeServer, json, noContent, sessionBody } from '../testing/fakeServer';
import { createClient } from './client';
import { ApiError } from './errors';

function client(server: ReturnType<typeof fakeServer>, onUnauthenticated = vi.fn()) {
  return { ...createClient({ fetch: server.fetch, onUnauthenticated }), onUnauthenticated };
}

async function failureOf(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ApiError) {
      return error;
    }
    throw error;
  }
  throw new Error('the request did not fail');
}

describe('call', () => {
  test('sends the credentials to this origin only and never follows a redirect', async () => {
    const server = fakeServer({ 'GET /api/v1/session': () => json(200, sessionBody()) });
    await client(server).call('getSession', {});
    const [request] = server.requests;
    expect(request?.credentials).toBe('same-origin');
    expect(request?.redirect).toBe('error');
    expect(request?.headers.Accept).toBe('application/json');
    expect(request?.headers['Content-Type']).toBeUndefined();
  });

  test('asks the browser not to store the answer', async () => {
    const server = fakeServer({ 'GET /api/v1/session': () => json(200, sessionBody()) });
    await client(server).call('getSession', {});
    expect(server.requests[0]?.cache).toBe('no-store');
  });

  test('ends a request that takes too long, as a failure of the network', { timeout: 2000 }, async () => {
    // The fake never answers; the client has to give up on its own.
    const silent = createClient({
      fetch: (_url, init) =>
        new Promise((_resolve, reject) => {
          init.signal?.addEventListener('abort', () => reject(new DOMException('the signal timed out', 'TimeoutError')));
        }),
      timeout: 10,
    });
    expect((await failureOf(silent.call('getSession', {}))).kind).toBe('network');
  });

  test('sends a body as JSON', async () => {
    const server = fakeServer({ 'POST /api/v1/session': () => json(200, sessionBody()) });
    await client(server).call('signIn', { body: { email: 'a@example.com', password: 'secret' } });
    expect(server.requests[0]?.headers['Content-Type']).toBe('application/json');
    expect(server.requests[0]?.body).toEqual({ email: 'a@example.com', password: 'secret' });
  });

  test('returns the status with the body that belongs to it', async () => {
    const server = fakeServer({
      'POST /api/v1/session': () => json(202, { second_factor: 'totp', expires_at: '2026-10-22T20:05:00Z' }),
    });
    const result = await client(server).call('signIn', { body: { email: 'a@example.com', password: 'secret' } });
    expect(result.status).toBe(202);
    expect(result.body).toEqual({ second_factor: 'totp', expires_at: '2026-10-22T20:05:00Z' });
  });

  test('answers a 204 without a body', async () => {
    const server = fakeServer({ 'DELETE /api/v1/session': noContent });
    expect(await client(server).call('signOut', {})).toEqual({ status: 204, body: undefined });
  });

  test('puts path parameters in, escaped, and leaves out query parameters that are not set', async () => {
    const server = fakeServer({ 'GET /api/v1/incidents/a%2Fb': () => json(404, {}), 'GET /api/v1/incidents': () => json(200, {}) });
    await failureOf(client(server).call('getIncident', { path: { id: 'a/b' } }));
    await client(server).call('listIncidents', { query: { limit: 10, status: undefined } });
    expect(server.requests.map((r) => r.url)).toEqual(['/api/v1/incidents/a%2Fb', '/api/v1/incidents?limit=10']);
  });

  test('refuses an operation that the browser navigates to', async () => {
    await expect(client(fakeServer({})).call('beginOIDCSignIn', {})).rejects.toThrow('navigation');
  });
});

describe('failures', () => {
  test('are mapped to a kind, whatever the message says', async () => {
    const server = fakeServer({ 'POST /api/v1/session': () => failure(401, 'invalid_credentials') });
    const error = await failureOf(client(server).call('signIn', { body: { email: 'a', password: 'b' } }));
    expect(error.kind).toBe('invalid_credentials');
    expect(error.message).not.toContain('message that the console must never show');
  });

  test('keep the delay of a lock', async () => {
    const server = fakeServer({
      'POST /api/v1/session': () => failure(403, 'account_locked', { 'Retry-After': '840' }),
    });
    const error = await failureOf(client(server).call('signIn', { body: { email: 'a', password: 'b' } }));
    expect([error.kind, error.retryAfter]).toEqual(['account_locked', 840]);
  });

  test('ignore a delay that is not a number', async () => {
    const server = fakeServer({
      'POST /api/v1/session': () => failure(403, 'account_locked', { 'Retry-After': 'Wed, 21 Oct 2026 07:28:00 GMT' }),
    });
    const error = await failureOf(client(server).call('signIn', { body: { email: 'a', password: 'b' } }));
    expect(error.retryAfter).toBeUndefined();
  });

  test('of a proxy, with a page instead of our JSON, are mapped by their status', async () => {
    const server = fakeServer({
      'POST /api/v1/session': () => new Response('<html>Too many requests</html>', { status: 429, headers: { 'Retry-After': '30' } }),
    });
    const error = await failureOf(client(server).call('signIn', { body: { email: 'a', password: 'b' } }));
    expect([error.kind, error.retryAfter]).toEqual(['rate_limited', 30]);
  });

  test('of the network are their own kind', async () => {
    const down = createClient({ fetch: () => Promise.reject(new TypeError('Failed to fetch')) });
    expect((await failureOf(down.call('getSession', {}))).kind).toBe('network');
  });

  test('a success that is not JSON is a server error', async () => {
    const server = fakeServer({ 'GET /api/v1/session': () => new Response('<html>', { status: 200 }) });
    expect((await failureOf(client(server).call('getSession', {}))).kind).toBe('server');
  });
});

// A 401 of a public operation says that the password is wrong. Only a 401 of an
// operation that needs a session says that the session has ended.
describe('the end of a session', () => {
  test('is reported when a request that needs a session finds none', async () => {
    const server = fakeServer({ 'GET /api/v1/incidents': () => failure(401, 'unauthenticated') });
    const c = client(server);
    expect((await failureOf(c.call('listIncidents', {}))).kind).toBe('unauthenticated');
    expect(c.onUnauthenticated).toHaveBeenCalledOnce();
  });

  test('is not reported for the wrong password of a sign-in', async () => {
    const server = fakeServer({ 'POST /api/v1/session': () => failure(401, 'invalid_credentials') });
    const c = client(server);
    await failureOf(c.call('signIn', { body: { email: 'a', password: 'b' } }));
    expect(c.onUnauthenticated).not.toHaveBeenCalled();
  });

  // A reverse proxy in front of the console can answer a sign-in with a plain 401,
  // such as for basic authentication. That is no session that ended.
  test('is not reported for a 401 without a code of an operation that is public', async () => {
    const server = fakeServer({ 'POST /api/v1/session': () => new Response('Unauthorized', { status: 401 }) });
    const c = client(server);
    expect((await failureOf(c.call('signIn', { body: { email: 'a', password: 'b' } }))).kind).toBe('unauthenticated');
    expect(c.onUnauthenticated).not.toHaveBeenCalled();
  });

  test('is not reported for a wrong code of the second factor', async () => {
    const server = fakeServer({ 'POST /api/v1/session/second-factor': () => failure(401, 'invalid_code') });
    const c = client(server);
    await failureOf(c.call('completeSignIn', { body: { code: '123456' } }));
    expect(c.onUnauthenticated).not.toHaveBeenCalled();
  });
});
