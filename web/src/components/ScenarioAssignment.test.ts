// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises, mount } from '@vue/test-utils';
import { afterEach, expect, test, vi } from 'vitest';
import { json, scenario } from '../testing/fakeServer';
import ScenarioAssignment from './ScenarioAssignment.vue';

afterEach(() => {
  vi.unstubAllGlobals();
});

// Two answers that arrive in the other order than they were asked for must not leave the
// name of the scenario that was asked for first.
test('shows the scenario that was asked for last, whatever the order of the answers', async () => {
  const waiting = new Map<string, (response: Response) => void>();
  vi.stubGlobal('fetch', (url: string) => new Promise<Response>((resolve) => waiting.set(url, resolve)));
  const first = scenario({ id: 'aaaaaaaa-1111-4222-8333-944444444444', name: 'First story' });
  const second = scenario({ id: 'bbbbbbbb-1111-4222-8333-944444444444', name: 'Second story' });
  const wrapper = mount(ScenarioAssignment, {
    props: { kind: 'honeytoken', resourceId: 'c0ffee00-1111-4222-8333-944444444444', scenarioId: first.id, canWrite: false },
    global: { stubs: { RouterLink: { template: '<a><slot /></a>' } } },
  });
  await flushPromises();
  await wrapper.setProps({ scenarioId: second.id });
  await flushPromises();
  waiting.get(`/api/v1/scenarios/${second.id}`)?.(json(200, second));
  await flushPromises();
  waiting.get(`/api/v1/scenarios/${first.id}`)?.(json(200, first));
  await flushPromises();
  expect(wrapper.text()).toContain('Second story');
  expect(wrapper.text()).not.toContain('First story');
});
