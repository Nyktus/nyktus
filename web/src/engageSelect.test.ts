// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises } from '@vue/test-utils';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { boot, submit, type } from './testing/boot';
import { fakeServer, json, scenario, sessionBody } from './testing/fakeServer';

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = '';
  history.replaceState(null, '', '/');
});

function server(extra: Record<string, () => Response> = {}) {
  return fakeServer({
    'GET /api/v1/session': () => json(200, sessionBody('admin')),
    'POST /api/v1/scenarios': () => json(201, scenario()),
    ...extra,
  });
}

// The group is plain checkboxes in a fieldset, so the browser brings the keyboard and the announcements; what the
// page must do is name the group, describe it and label every box.
describe('the choice of Engage activities', () => {
  test('is a named group of labelled checkboxes that the keyboard reaches', async () => {
    const { wrapper } = await boot(server(), '/scenarios/new');
    const group = wrapper.get('fieldset');
    expect(group.get('legend').text()).toBe('Engage activities');
    const hint = group.get(`#${group.attributes('aria-describedby')}`);
    expect(hint.text()).toContain('MITRE names them in English only.');
    const boxes = group.findAll('input');
    expect(boxes).toHaveLength(3);
    for (const box of boxes) {
      expect(box.attributes('type')).toBe('checkbox');
      expect(box.attributes('disabled')).toBeUndefined();
      expect(box.attributes('tabindex')).toBeUndefined();
      // The label wraps the box, so a click on the name and the name read aloud belong to it.
      expect(box.element.closest('label')?.textContent?.trim()).not.toBe('');
    }
  });

  test('says that it is loading while the names are on the way', async () => {
    const answers: ((response: Response) => void)[] = [];
    const s = server({ 'GET /api/v1/catalog/engage': () => new Promise<Response>((resolve) => answers.push(resolve)) as never });
    const { wrapper } = await boot(s, '/scenarios/new');
    expect(wrapper.get('fieldset [role=status]').text()).toContain('Loading');
    expect(wrapper.findAll('fieldset input')).toHaveLength(0);
    answers[0]?.(json(200, { activities: [{ id: 'EAC0005', name: 'Lures' }] }));
    await flushPromises();
    expect(wrapper.find('fieldset [role=status]').exists()).toBe(false);
    expect(wrapper.findAll('fieldset input')).toHaveLength(1);
  });

  test('keeps the order of the list, whatever the order of the clicks, and drops a box that is cleared', async () => {
    const s = server();
    const { wrapper } = await boot(s, '/scenarios/new');
    const boxes = wrapper.findAll('fieldset input');
    await boxes[2]?.setValue(true);
    await boxes[0]?.setValue(true);
    await boxes[1]?.setValue(true);
    await boxes[1]?.setValue(false);
    await type(wrapper, '#name', 'Story');
    await submit(wrapper);
    expect(s.requests.find((r) => r.method === 'POST')?.body).toMatchObject({ engage_activities: ['EAC0005', 'EAC0011'] });
  });

  test('asks the server for the names once, however many pages show them', async () => {
    const s = server();
    const { wrapper, router } = await boot(s, '/scenarios/new');
    await router.push('/catalog');
    await flushPromises();
    await router.push('/scenarios/new');
    await flushPromises();
    expect(wrapper.find('fieldset').exists()).toBe(true);
    expect(s.requests.filter((r) => r.url === '/api/v1/catalog/engage')).toHaveLength(1);
  });

  test('asks again on the next page when the names could not be read', async () => {
    const answers = [new Response('{}', { status: 503, headers: { 'Content-Type': 'application/json' } })];
    const s = server({
      'GET /api/v1/catalog/engage': () => answers.shift() ?? json(200, { activities: [{ id: 'EAC0005', name: 'Lures' }] }),
    });
    const { wrapper, router } = await boot(s, '/scenarios/new');
    expect(wrapper.find('fieldset [role=alert]').exists()).toBe(true);
    await router.push('/scenarios');
    await flushPromises();
    await router.push('/scenarios/new');
    await flushPromises();
    expect(wrapper.find('fieldset [role=alert]').exists()).toBe(false);
    expect(wrapper.get('fieldset label').text()).toBe('Lures (EAC0005)');
  });

  test('shows names and identifiers as text', async () => {
    const s = server({ 'GET /api/v1/catalog/engage': () => json(200, { activities: [{ id: 'EAC0005', name: '<b>Lures</b>' }] }) });
    const { wrapper } = await boot(s, '/scenarios/new');
    expect(wrapper.get('fieldset label').text()).toBe('<b>Lures</b> (EAC0005)');
    expect(wrapper.find('fieldset b').exists()).toBe(false);
  });
});
