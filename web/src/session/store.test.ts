// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, test } from 'vitest';
import { createClient } from '../api/client';
import { ApiError } from '../api/errors';
import { rolePermissions } from '../api/generated';
import { failure, fakeServer, json, noContent, sessionBody } from '../testing/fakeServer';
import { createSessionStore } from './store';

function store(server: ReturnType<typeof fakeServer>) {
  return createSessionStore(createClient({ fetch: server.fetch }));
}

describe('ensureLoaded', () => {
  test('signs the user in when the server knows the session, and asks once', async () => {
    const server = fakeServer({ 'GET /api/v1/session': () => json(200, sessionBody('viewer', 'Vera')) });
    const s = store(server);
    expect(s.state.status).toBe('unknown');
    await Promise.all([s.ensureLoaded(), s.ensureLoaded()]);
    await s.ensureLoaded();
    expect(s.state.status).toBe('signed-in');
    expect(s.state.session?.user.display_name).toBe('Vera');
    expect(server.requests).toHaveLength(1);
  });

  test('signs the user out when there is no session', async () => {
    const s = store(fakeServer({ 'GET /api/v1/session': () => failure(401, 'unauthenticated') }));
    await s.ensureLoaded();
    expect(s.state.status).toBe('signed-out');
    expect(s.state.session).toBeUndefined();
  });

  test.each([
    ['a server that is busy', () => failure(503, 'unavailable')],
    ['a server that fails', () => failure(500, 'internal')],
    ['a limit of requests', () => failure(429, 'rate_limited')],
    ['a page of a proxy', () => new Response('<html>Bad gateway</html>', { status: 502 })],
  ])('does not sign the user out because of %s: it says nothing about the session', async (_name, answer) => {
    const s = store(fakeServer({ 'GET /api/v1/session': answer }));
    await s.ensureLoaded();
    expect(s.state.status).toBe('unavailable');
    expect(s.state.session).toBeUndefined();
  });

  test('does not sign the user out because the network is down', async () => {
    const s = createSessionStore(createClient({ fetch: () => Promise.reject(new TypeError('Failed to fetch')) }));
    await s.ensureLoaded();
    expect(s.state.status).toBe('unavailable');
  });

  test('asks again after a failure, and finds the session once the server answers', async () => {
    let answer: () => Response = () => failure(503, 'unavailable');
    const server = fakeServer({ 'GET /api/v1/session': () => answer() });
    const s = store(server);
    await s.ensureLoaded();
    expect(s.state.status).toBe('unavailable');
    answer = () => json(200, sessionBody('viewer', 'Vera'));
    await s.ensureLoaded();
    expect(s.state.status).toBe('signed-in');
    expect(server.requests).toHaveLength(2);
  });
});

describe('signIn', () => {
  test('starts the session', async () => {
    const s = store(fakeServer({ 'POST /api/v1/session': () => json(200, sessionBody()) }));
    expect(await s.signIn('ada@example.com', 'a long password')).toEqual({ next: 'done' });
    expect(s.state.status).toBe('signed-in');
  });

  test('waits for the second factor without a session', async () => {
    const s = store(
      fakeServer({ 'POST /api/v1/session': () => json(202, { second_factor: 'totp', expires_at: '2026-10-22T20:05:00Z' }) }),
    );
    expect(await s.signIn('ada@example.com', 'a long password')).toEqual({ next: 'second-factor' });
    expect(s.state.status).not.toBe('signed-in');
    expect(s.state.session).toBeUndefined();
  });

  test('keeps neither the password nor the address in its state', async () => {
    const s = store(fakeServer({ 'POST /api/v1/session': () => json(200, sessionBody()) }));
    await s.signIn('typed@example.com', 'the password that was typed');
    expect(JSON.stringify(s.state)).not.toContain('the password that was typed');
    expect(JSON.stringify(s.state)).not.toContain('typed@example.com');
  });

  test('passes the failure on and stays signed out', async () => {
    const s = store(fakeServer({ 'POST /api/v1/session': () => failure(401, 'invalid_credentials') }));
    await expect(s.signIn('ada@example.com', 'wrong')).rejects.toMatchObject({ kind: 'invalid_credentials' });
    expect(s.state.status).toBe('unknown');
  });
});

describe('completeSecondFactor', () => {
  test('starts the session with a code or a recovery code', async () => {
    const server = fakeServer({ 'POST /api/v1/session/second-factor': () => json(200, sessionBody()) });
    const s = store(server);
    await s.completeSecondFactor({ code: '123456' });
    await s.completeSecondFactor({ recovery_code: 'abcd-efgh-ijkl-mnop' });
    expect(server.requests.map((r) => r.body)).toEqual([{ code: '123456' }, { recovery_code: 'abcd-efgh-ijkl-mnop' }]);
    expect(s.state.status).toBe('signed-in');
  });
});

describe('signOut', () => {
  async function signedIn(server: ReturnType<typeof fakeServer>) {
    const s = store(server);
    await s.ensureLoaded();
    return s;
  }

  test('ends the session', async () => {
    const s = await signedIn(fakeServer({ 'GET /api/v1/session': () => json(200, sessionBody()), 'DELETE /api/v1/session': noContent }));
    await s.signOut();
    expect(s.state.status).toBe('signed-out');
    expect(s.state.session).toBeUndefined();
    expect(s.state.leftOnPurpose).toBe(true);
  });

  test('is told apart from a session that ended, and from the next sign-in', async () => {
    const s = await signedIn(fakeServer({ 'GET /api/v1/session': () => json(200, sessionBody()), 'POST /api/v1/session': () => json(200, sessionBody()) }));
    s.expire();
    expect(s.state.leftOnPurpose).toBe(false);
    await s.signOut().catch(() => undefined);
    await s.signIn('ada@example.com', 'a long password');
    expect(s.state.leftOnPurpose).toBe(false);
  });

  test('succeeds when the session was already gone', async () => {
    const s = await signedIn(
      fakeServer({ 'GET /api/v1/session': () => json(200, sessionBody()), 'DELETE /api/v1/session': () => failure(401, 'unauthenticated') }),
    );
    await s.signOut();
    expect(s.state.status).toBe('signed-out');
  });

  test('stays signed in when the server could not be reached, so that the user knows', async () => {
    const s = await signedIn(
      fakeServer({ 'GET /api/v1/session': () => json(200, sessionBody()), 'DELETE /api/v1/session': () => failure(503, 'unavailable') }),
    );
    await expect(s.signOut()).rejects.toBeInstanceOf(ApiError);
    expect(s.state.status).toBe('signed-in');
  });
});

describe('can', () => {
  test('follows the role', async () => {
    const s = store(fakeServer({ 'GET /api/v1/session': () => json(200, sessionBody('viewer')) }));
    expect(s.can('incidents:read')).toBe(false);
    await s.ensureLoaded();
    expect(s.can('incidents:read')).toBe(true);
    expect(s.can('incidents:write')).toBe(false);
    expect(s.can('users:read')).toBe(false);
  });

  test('grants nothing once the session has ended', async () => {
    const s = store(fakeServer({ 'GET /api/v1/session': () => json(200, sessionBody('admin')) }));
    await s.ensureLoaded();
    expect(s.can('users:write')).toBe(true);
    s.expire();
    expect(s.can('users:write')).toBe(false);
  });
});

// The viewer reads and never writes, on the server and so in the table that the
// console hides pages by.
test('a viewer has no permission to write', () => {
  expect(rolePermissions.viewer.filter((p) => p.endsWith(':write'))).toEqual([]);
  expect(rolePermissions.user.filter((p) => p.startsWith('users:') || p.startsWith('api_keys:') || p.startsWith('alert_channels:'))).toEqual(
    [],
  );
});
