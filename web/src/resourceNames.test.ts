// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { afterEach, expect, test, vi } from 'vitest';
import { json, scenario } from './testing/fakeServer';
import { useResourceNames } from './resourceNames';

afterEach(() => {
  vi.unstubAllGlobals();
});

// Every name is a request of its own, so a page of fifty incidents must not send fifty at once.
test('asks for at most six names at the same time, and names every resource', async () => {
  let running = 0;
  let most = 0;
  vi.stubGlobal('fetch', async (url: string) => {
    running++;
    most = Math.max(most, running);
    await new Promise((resolve) => setTimeout(resolve, 0));
    running--;
    const id = url.split('/').pop() ?? '';
    return json(200, scenario({ id, name: `name of ${id}` }));
  });
  const names = useResourceNames();
  const resources = Array.from({ length: 30 }, (_, i) => ({ resource_type: 'scenario' as const, resource_id: `aaaaaaaa-0000-4222-8333-${String(i).padStart(12, '0')}` }));
  await names.resolve(resources);
  expect(most).toBe(6);
  expect(Object.keys(names.entries.value)).toHaveLength(30);
  expect(Object.values(names.entries.value).every((e) => e.state === 'named')).toBe(true);
});

test('asks again for a name that could not be read, and not for one that is there', async () => {
  const fetches: string[] = [];
  let up = false;
  vi.stubGlobal('fetch', (url: string) => {
    fetches.push(url);
    return Promise.resolve(up ? json(200, scenario({ name: 'Named' })) : new Response('{}', { status: 503, headers: { 'Content-Type': 'application/json' } }));
  });
  const names = useResourceNames();
  const one = [{ resource_type: 'scenario' as const, resource_id: 'aaaaaaaa-0000-4222-8333-000000000001' }];
  await names.resolve(one);
  expect(Object.values(names.entries.value)[0]).toEqual({ state: 'unknown' });
  up = true;
  await names.resolve(one);
  expect(Object.values(names.entries.value)[0]).toEqual({ state: 'named', name: 'Named' });
  await names.resolve(one);
  expect(fetches).toHaveLength(2);
});
