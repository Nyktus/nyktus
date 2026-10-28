// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises } from '@vue/test-utils';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { arrive, boot } from './testing/boot';
import {
  dnsEvent,
  event,
  eventId,
  failure,
  fakeServer,
  honeypot,
  honeypotId,
  honeytoken,
  incident,
  incidentId,
  json,
  scenario,
  scenarioId,
  sensorEvent,
  sessionBody,
  type Handler,
} from './testing/fakeServer';

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  document.body.innerHTML = '';
  history.replaceState(null, '', '/');
});

type Role = 'admin' | 'user' | 'viewer';

const detail = `/api/v1/incidents/${incidentId}`;
const active = '/api/v1/incidents?limit=50&status=open%2Cacknowledged';

function server(role: Role = 'admin', extra: Record<string, Handler> = {}) {
  return fakeServer({
    'GET /api/v1/session': () => json(200, sessionBody(role)),
    'GET /api/v1/incidents': () => json(200, { incidents: [incident()] }),
    [`GET ${detail}`]: () => json(200, incident()),
    [`GET ${detail}/deliveries`]: () => json(200, { deliveries: [] }),
    'GET /api/v1/events': () => json(200, { events: [event()] }),
    [`GET /api/v1/events/${eventId}`]: () => json(200, event()),
    [`GET /api/v1/scenarios/${scenarioId}`]: () => json(200, scenario()),
    [`GET /api/v1/honeytokens/${honeytoken().id}`]: () => json(200, honeytoken()),
    [`GET /api/v1/honeypots/${honeypotId}`]: () => json(200, honeypot()),
    ...extra,
  });
}

const urls = (s: ReturnType<typeof server>, prefix: string): string[] => s.requests.map((r) => r.url).filter((u) => u.startsWith(prefix));
const patches = (s: ReturnType<typeof server>) => s.requests.filter((r) => r.method === 'PATCH');
const button = (wrapper: Awaited<ReturnType<typeof boot>>['wrapper'], label: string) => wrapper.findAll('button').find((b) => b.text() === label);

describe('the list of incidents', () => {
  test('shows the status, the severity, the resource by name and the times', async () => {
    const closed = incident({ id: 'f00dfeed-2222-4222-8333-944444444444', status: 'closed', severity: 'low', resource_type: 'honeytoken', resource_id: honeytoken().id, event_count: 7 });
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/incidents': () => json(200, { incidents: [incident(), closed] }) }), '/incidents');
    const rows = wrapper.findAll('tbody tr');
    expect(rows).toHaveLength(2);
    expect(rows[0]?.text()).toContain('Open');
    expect(rows[0]?.text()).toContain('High');
    expect(rows[0]?.text()).toContain('Scenario');
    expect(rows[0]?.text()).toContain('Stolen backup');
    expect(rows[1]?.text()).toContain('Closed');
    expect(rows[1]?.text()).toContain('Backup share link');
    expect(rows[1]?.text()).toContain('7');
    expect(rows[0]?.get('a').attributes('href')).toBe(`/incidents/${incidentId}`);
    expect(rows[0]?.find(`a[href="/scenarios/${scenarioId}"]`).exists()).toBe(true);
  });

  test('asks for the incidents that are not closed, and for the others when the filter changes', async () => {
    const s = server();
    const { wrapper } = await boot(s, '/incidents');
    await wrapper.get('#filter-status').setValue('');
    await flushPromises();
    await wrapper.get('#filter-status').setValue('closed');
    await flushPromises();
    expect(urls(s, '/api/v1/incidents?')).toEqual([active, '/api/v1/incidents?limit=50', '/api/v1/incidents?limit=50&status=closed']);
  });

  test('says so when none wait, when there are none at all, and when the filter finds none', async () => {
    const s = server('admin', { 'GET /api/v1/incidents': () => json(200, { incidents: [] }) });
    const { wrapper } = await boot(s, '/incidents');
    expect(wrapper.text()).toContain('No unprocessed incidents.');
    await wrapper.get('#filter-status').setValue('');
    await flushPromises();
    expect(wrapper.text()).toContain('There are no incidents yet.');
    await wrapper.get('#filter-status').setValue('closed');
    await flushPromises();
    expect(wrapper.text()).toContain('No incidents found.');
  });

  test('reads the next page with the cursor of the last one', async () => {
    const second = incident({ id: 'f00dfeed-3333-4222-8333-944444444444', severity: 'critical' });
    const s = server('admin', {
      'GET /api/v1/incidents': (r) =>
        r.url.includes('cursor=next-page') ? json(200, { incidents: [second] }) : json(200, { incidents: [incident()], next_cursor: 'next-page' }),
    });
    const { wrapper } = await boot(s, '/incidents');
    expect(wrapper.findAll('tbody tr')).toHaveLength(1);
    await button(wrapper, 'Load more')!.trigger('click');
    await flushPromises();
    expect(wrapper.findAll('tbody tr')).toHaveLength(2);
    expect(urls(s, '/api/v1/incidents?').at(-1)).toBe('/api/v1/incidents?limit=50&cursor=next-page&status=open%2Cacknowledged');
    expect(button(wrapper, 'Load more')).toBeUndefined();
  });

  test('says so when the list cannot be loaded', async () => {
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/incidents': () => failure(500, 'internal_error') }), '/incidents');
    expect(wrapper.get('[role=alert]').text()).toContain('The incidents could not be loaded.');
  });

  test('asks for the name of a resource once, and shows what is gone by its identifier', async () => {
    const same = incident({ id: 'f00dfeed-4444-4222-8333-944444444444' });
    const gone = incident({ id: 'f00dfeed-5555-4222-8333-944444444444', resource_type: 'honeypot', resource_id: 'beefbeef-9999-4222-8333-944444444444' });
    const s = server('admin', { 'GET /api/v1/incidents': () => json(200, { incidents: [incident(), same, gone] }) });
    const { wrapper } = await boot(s, '/incidents');
    expect(urls(s, `/api/v1/scenarios/${scenarioId}`)).toHaveLength(1);
    const row = wrapper.findAll('tbody tr')[2]!;
    expect(row.text()).toContain('Deleted');
    expect(row.text()).toContain('beefbeef-9999-4222-8333-944444444444');
    expect(row.find('td:nth-child(4) a').exists()).toBe(false);
  });

  test('does not ask again for a resource of a later page', async () => {
    const second = incident({ id: 'f00dfeed-7777-4222-8333-944444444444' });
    const s = server('admin', {
      'GET /api/v1/incidents': (r) =>
        r.url.includes('cursor=next-page') ? json(200, { incidents: [second] }) : json(200, { incidents: [incident()], next_cursor: 'next-page' }),
    });
    const { wrapper } = await boot(s, '/incidents');
    await button(wrapper, 'Load more')!.trigger('click');
    await flushPromises();
    expect(wrapper.findAll('tbody tr')).toHaveLength(2);
    expect(urls(s, `/api/v1/scenarios/${scenarioId}`)).toHaveLength(1);
  });

  test('shows the identifier when the name cannot be read, and asks again when the list is loaded again', async () => {
    let answer: () => Response = () => failure(500, 'internal_error');
    const s = server('admin', { [`GET /api/v1/scenarios/${scenarioId}`]: () => answer() });
    const { wrapper } = await boot(s, '/incidents');
    expect(wrapper.findAll('tbody tr')[0]?.text()).toContain(scenarioId);
    answer = () => json(200, scenario());
    await button(wrapper, 'Refresh')!.trigger('click');
    await flushPromises();
    expect(wrapper.get('tbody td:nth-child(4) a').text()).toBe('Stolen backup');
    expect(urls(s, `/api/v1/scenarios/${scenarioId}`)).toHaveLength(2);
  });

  test('shows a name that is markup as text', async () => {
    const s = server('admin', { [`GET /api/v1/scenarios/${scenarioId}`]: () => json(200, scenario({ name: '<img src=x onerror=alert(1)>' })) });
    const { wrapper } = await boot(s, '/incidents');
    expect(wrapper.find('img[src=x]').exists()).toBe(false);
    expect(wrapper.get('tbody td:nth-child(4) a').text()).toBe('<img src=x onerror=alert(1)>');
  });

  test('is in the navigation of every role', async () => {
    for (const role of ['admin', 'user', 'viewer'] as const) {
      const { wrapper } = await boot(server(role), '/');
      expect(wrapper.findAll('nav a').map((a) => a.text())).toContain('Incidents');
      document.body.innerHTML = '';
    }
  });

  describe('looks for new incidents', () => {
    beforeEach(() => {
      // Only the interval is replaced: the rest of the test waits on real timers.
      vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
    });

    const newest = incident({ id: 'f00dfeed-6666-4222-8333-944444444444' });

    test('asks for the newest incident every minute and says so when there is a new one, without changing the list', async () => {
      const answers = [{ incidents: [incident()] }, { incidents: [newest] }];
      const s = server('admin', { 'GET /api/v1/incidents': (r) => json(200, r.url.includes('limit=1&') ? answers[1] : answers[0]) });
      const { wrapper } = await boot(s, '/incidents');
      expect(wrapper.text()).not.toContain('There are new incidents.');
      await vi.advanceTimersByTimeAsync(60_000);
      await flushPromises();
      expect(urls(s, '/api/v1/incidents?')).toEqual([active, '/api/v1/incidents?limit=1&status=open%2Cacknowledged']);
      expect(wrapper.get('[role=status]').text()).toContain('There are new incidents.');
      expect(wrapper.findAll('tbody tr')).toHaveLength(1);
      expect(wrapper.get('tbody a').attributes('href')).toBe(`/incidents/${incidentId}`);
    });

    // When the incident on top is closed by someone else, the one below it is the newest of the filter:
    // it is in the list already, so there is nothing new to show.
    test('says nothing when the newest incident is one that the list already has, below the top', async () => {
      const second = incident({ id: 'f00dfeed-8888-4222-8333-944444444444' });
      const s = server('admin', { 'GET /api/v1/incidents': (r) => json(200, r.url.includes('limit=1&') ? { incidents: [second] } : { incidents: [incident(), second] }) });
      const { wrapper } = await boot(s, '/incidents');
      await vi.advanceTimersByTimeAsync(60_000);
      await flushPromises();
      expect(urls(s, '/api/v1/incidents?limit=1')).toHaveLength(1);
      expect(wrapper.text()).not.toContain('There are new incidents.');
    });

    test('says nothing while the newest incident is the one on top', async () => {
      const s = server();
      const { wrapper } = await boot(s, '/incidents');
      await vi.advanceTimersByTimeAsync(180_000);
      await flushPromises();
      expect(urls(s, '/api/v1/incidents?limit=1')).toHaveLength(3);
      expect(wrapper.text()).not.toContain('There are new incidents.');
    });

    test('loads the list again when the user asks for it, and the notice goes', async () => {
      let answer = incident();
      const s = server('admin', { 'GET /api/v1/incidents': () => json(200, { incidents: [answer] }) });
      const { wrapper } = await boot(s, '/incidents');
      answer = newest;
      await vi.advanceTimersByTimeAsync(60_000);
      await flushPromises();
      await button(wrapper, 'Show them')!.trigger('click');
      await flushPromises();
      expect(wrapper.text()).not.toContain('There are new incidents.');
      expect(wrapper.get('tbody a').attributes('href')).toBe(`/incidents/${newest.id}`);
    });

    test('does not ask while the tab is hidden', async () => {
      const s = server();
      await boot(s, '/incidents');
      Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });
      try {
        await vi.advanceTimersByTimeAsync(120_000);
        await flushPromises();
      } finally {
        Reflect.deleteProperty(document, 'visibilityState');
      }
      expect(urls(s, '/api/v1/incidents?limit=1')).toEqual([]);
    });

    test('says nothing when the look fails', async () => {
      const s = server('admin', { 'GET /api/v1/incidents': (r) => (r.url.includes('limit=1&') ? failure(500, 'internal_error') : json(200, { incidents: [incident()] })) });
      const { wrapper } = await boot(s, '/incidents');
      await vi.advanceTimersByTimeAsync(60_000);
      await flushPromises();
      expect(wrapper.find('[role=alert]').exists()).toBe(false);
      expect(wrapper.text()).not.toContain('There are new incidents.');
    });

    test('stops when the user leaves the page', async () => {
      const s = server();
      const { router } = await boot(s, '/incidents');
      await router.push('/forbidden');
      await arrive(router, 'forbidden');
      await vi.advanceTimersByTimeAsync(300_000);
      await flushPromises();
      expect(urls(s, '/api/v1/incidents?limit=1')).toEqual([]);
    });

    test('does not ask while the list is still loading', async () => {
      let release: () => void = () => {};
      const slow = new Promise<void>((resolve) => {
        release = resolve;
      });
      const s = server('admin', {
        'GET /api/v1/incidents': async () => {
          await slow;
          return json(200, { incidents: [incident()] });
        },
      });
      await boot(s, '/incidents');
      await vi.advanceTimersByTimeAsync(60_000);
      await flushPromises();
      expect(urls(s, '/api/v1/incidents?limit=1')).toEqual([]);
      release();
      await flushPromises();
    });

    test('ignores an answer for a filter that the user has left', async () => {
      let release: () => void = () => {};
      const slow = new Promise<void>((resolve) => {
        release = resolve;
      });
      const s = server('admin', {
        'GET /api/v1/incidents': async (r) => {
          if (r.url === '/api/v1/incidents?limit=1&status=open%2Cacknowledged') {
            await slow;
            return json(200, { incidents: [newest] });
          }
          return json(200, { incidents: [incident()] });
        },
      });
      const { wrapper } = await boot(s, '/incidents');
      await vi.advanceTimersByTimeAsync(60_000);
      await wrapper.get('#filter-status').setValue('closed');
      await flushPromises();
      release();
      await flushPromises();
      expect(wrapper.text()).not.toContain('There are new incidents.');
    });
  });
});

describe('an incident', () => {
  const path = `/incidents/${incidentId}`;

  test('shows what the server knows', async () => {
    const s = server('admin', {
      [`GET ${detail}`]: () =>
        json(200, incident({ status: 'acknowledged', acknowledged_at: '2026-10-22T08:00:00Z', event_count: 5, techniques: ['T1078', 'T1110'] })),
    });
    const { wrapper } = await boot(s, path);
    const text = wrapper.get('dl').text();
    expect(text).toContain('Stolen backup');
    expect(text).toContain('T1078, T1110');
    expect(text).toContain('5');
    expect(text).toContain('Acknowledged');
    expect(wrapper.get('.badges').text()).toContain('Acknowledged');
    expect(wrapper.get('dl a').attributes('href')).toBe(`/scenarios/${scenarioId}`);
  });

  test('says what was overridden', async () => {
    const s = server('admin', {
      [`GET ${detail}`]: () =>
        json(200, incident({ severity: 'info', severity_override: 'info', techniques: [], techniques_override: [], event_techniques: ['T1078'] })),
    });
    const { wrapper } = await boot(s, path);
    expect(wrapper.get('dl').text()).toContain('Recommended severity: High.');
    expect(wrapper.get('dl').text()).toContain('Techniques of the events');
    expect((wrapper.get('#severity').element as HTMLSelectElement).value).toBe('info');
    expect((wrapper.get('#override-techniques').element as HTMLInputElement).checked).toBe(true);
  });

  test('shows no override where there is none, and the notes only where there is no form', async () => {
    const { wrapper } = await boot(server(), path);
    expect(wrapper.get('dl').text()).not.toContain('Overridden');
    expect(wrapper.get('dl').text()).not.toContain('Techniques of the events');
    expect(wrapper.find('dd.notes').exists()).toBe(false);
  });

  test('says when it does not exist', async () => {
    const { wrapper } = await boot(server('admin', { [`GET ${detail}`]: () => failure(404, 'not_found') }), path);
    expect(wrapper.text()).toContain('Nothing found here.');
  });

  test('says when it cannot be loaded', async () => {
    const { wrapper } = await boot(server('admin', { [`GET ${detail}`]: () => failure(500, 'internal_error') }), path);
    expect(wrapper.get('[role=alert]').text()).toBe('Something went wrong on the server.');
  });

  describe('moves its status', () => {
    test('to acknowledged with that alone, and then offers only to close it', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => json(200, incident({ status: 'acknowledged', acknowledged_at: '2026-10-22T08:00:00Z' })) });
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'Acknowledge')!.trigger('click');
      await flushPromises();
      expect(patches(s).map((r) => r.body)).toEqual([{ status: 'acknowledged' }]);
      expect(wrapper.get('.badges').text()).toContain('Acknowledged');
      expect(button(wrapper, 'Acknowledge')).toBeUndefined();
      expect(button(wrapper, 'Close')).toBeDefined();
    });

    test('to closed only after the user confirms what that means', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => json(200, incident({ status: 'closed', closed_at: '2026-10-22T09:00:00Z' })) });
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'Close')!.trigger('click');
      await flushPromises();
      expect(wrapper.get('dialog[open] h2').text()).toBe('Close this incident?');
      expect(wrapper.get('dialog[open]').text()).toContain('cannot be reopened');
      expect(patches(s)).toHaveLength(0);
      await wrapper.get('dialog[open] .danger').trigger('click');
      await flushPromises();
      expect(patches(s).map((r) => r.body)).toEqual([{ status: 'closed' }]);
      expect(wrapper.get('.badges').text()).toContain('Closed');
      expect(wrapper.text()).toContain('This incident is closed. You can still change the notes and the severity.');
      expect(button(wrapper, 'Close')).toBeUndefined();
      expect(button(wrapper, 'Acknowledge')).toBeUndefined();
    });

    test('does nothing when the user cancels the closing', async () => {
      const s = server();
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'Close')!.trigger('click');
      await flushPromises();
      await wrapper.get('dialog[open] .button-ghost').trigger('click');
      await flushPromises();
      expect(patches(s)).toHaveLength(0);
      expect(wrapper.find('dialog[open]').exists()).toBe(false);
    });

    test('offers nothing for a closed incident, but still the notes', async () => {
      const s = server('admin', { [`GET ${detail}`]: () => json(200, incident({ status: 'closed', closed_at: '2026-10-22T09:00:00Z' })) });
      const { wrapper } = await boot(s, path);
      expect(button(wrapper, 'Close')).toBeUndefined();
      expect(button(wrapper, 'Acknowledge')).toBeUndefined();
      expect(wrapper.find('#notes').exists()).toBe(true);
    });

    test('says that it is not possible in this state and shows where the incident is, when the server refuses', async () => {
      let status: 'open' | 'closed' = 'open';
      const s = server('admin', {
        [`GET ${detail}`]: () => json(200, incident({ status })),
        [`PATCH ${detail}`]: () => {
          status = 'closed';
          return failure(409, 'invalid_state');
        },
      });
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'Acknowledge')!.trigger('click');
      await flushPromises();
      expect(wrapper.get('[role=alert]').text()).toContain('Invalid state. Reload the page and try again.');
      expect(wrapper.get('.badges').text()).toContain('Closed');
      expect(button(wrapper, 'Acknowledge')).toBeUndefined();
    });

    test('closes the dialog when the server refuses, and says why', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => failure(409, 'invalid_state') });
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'Close')!.trigger('click');
      await flushPromises();
      await wrapper.get('dialog[open] .danger').trigger('click');
      await flushPromises();
      expect(wrapper.find('dialog[open]').exists()).toBe(false);
      expect(wrapper.get('[role=alert]').text()).toContain('Invalid state. Reload the page and try again.');
    });

    test('does not show the message of the server', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => failure(500, 'internal_error') });
      const { wrapper } = await boot(s, path);
      await button(wrapper, 'Acknowledge')!.trigger('click');
      await flushPromises();
      expect(wrapper.get('[role=alert]').text()).toBe('Something went wrong on the server.');
    });

    test('does not discard what the user typed in the notes', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => json(200, incident({ status: 'acknowledged' })) });
      const { wrapper } = await boot(s, path);
      await wrapper.get('#notes').setValue('Checking fs01.');
      await button(wrapper, 'Acknowledge')!.trigger('click');
      await flushPromises();
      expect((wrapper.get('#notes').element as HTMLTextAreaElement).value).toBe('Checking fs01.');
    });
  });

  describe('is triaged with the form', () => {
    const submit = async (wrapper: Awaited<ReturnType<typeof boot>>['wrapper']) => {
      await wrapper.get('form').trigger('submit');
      await flushPromises();
    };

    test('sends only the notes when only they changed', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => json(200, incident({ notes: 'Checking fs01.' })) });
      const { wrapper } = await boot(s, path);
      await wrapper.get('#notes').setValue('Checking fs01.');
      await submit(wrapper);
      expect(patches(s).map((r) => r.body)).toEqual([{ notes: 'Checking fs01.' }]);
      expect(wrapper.get('[role=status]').text()).toBe('Saved.');
    });

    test('leaves an override that did not change out of the request', async () => {
      const s = server('admin', {
        [`GET ${detail}`]: () => json(200, incident({ severity_override: 'low', techniques_override: ['T1110'] })),
        [`PATCH ${detail}`]: () => json(200, incident({ severity_override: 'low', techniques_override: ['T1110'], notes: 'x' })),
      });
      const { wrapper } = await boot(s, path);
      await wrapper.get('#notes').setValue('x');
      await submit(wrapper);
      expect(patches(s).map((r) => r.body)).toEqual([{ notes: 'x' }]);
      await wrapper.get('#techniques').setValue('t1110');
      await wrapper.get('#notes').setValue('xy');
      await submit(wrapper);
      expect(patches(s).map((r) => r.body)).toEqual([{ notes: 'x' }, { notes: 'xy' }]);
    });

    test('shows what the server saved, not what was typed', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => json(200, incident({ notes: 'Normalized.' })) });
      const { wrapper } = await boot(s, path);
      await wrapper.get('#notes').setValue('As typed.');
      await submit(wrapper);
      expect((wrapper.get('#notes').element as HTMLTextAreaElement).value).toBe('Normalized.');
    });

    test('sends no request when nothing changed', async () => {
      const s = server();
      const { wrapper } = await boot(s, path);
      await submit(wrapper);
      expect(patches(s)).toHaveLength(0);
      expect(wrapper.text()).toContain('Saved.');
    });

    test('overrides the severity, and removes the override with null', async () => {
      let current = incident();
      const s = server('admin', {
        [`GET ${detail}`]: () => json(200, current),
        [`PATCH ${detail}`]: (r) => {
          const body = r.body as { severity_override: 'info' | null };
          current = incident({ severity_override: body.severity_override, severity: body.severity_override ?? 'high' });
          return json(200, current);
        },
      });
      const { wrapper } = await boot(s, path);
      await wrapper.get('#severity').setValue('info');
      await submit(wrapper);
      await wrapper.get('#severity').setValue('');
      await submit(wrapper);
      expect(patches(s).map((r) => r.body)).toEqual([{ severity_override: 'info' }, { severity_override: null }]);
    });

    test('overrides the techniques with the identifiers, an empty list, and removes the override with null', async () => {
      let current = incident();
      const s = server('admin', {
        [`GET ${detail}`]: () => json(200, current),
        [`PATCH ${detail}`]: (r) => {
          const body = r.body as { techniques_override: string[] | null };
          current = incident({ techniques_override: body.techniques_override });
          return json(200, current);
        },
      });
      const { wrapper } = await boot(s, path);
      await wrapper.get('#override-techniques').setValue(true);
      await wrapper.get('#techniques').setValue('t1110, T1003.001 t1110');
      await submit(wrapper);
      await wrapper.get('#techniques').setValue('');
      await submit(wrapper);
      await wrapper.get('#override-techniques').setValue(false);
      await submit(wrapper);
      expect(patches(s).map((r) => r.body)).toEqual([
        { techniques_override: ['T1110', 'T1003.001'] },
        { techniques_override: [] },
        { techniques_override: null },
      ]);
    });

    test('starts the override from the techniques of the events', async () => {
      const { wrapper } = await boot(server('admin', { [`GET ${detail}`]: () => json(200, incident({ event_techniques: ['T1078', 'T1110'] })) }), path);
      await wrapper.get('#override-techniques').setValue(true);
      expect((wrapper.get('#techniques').element as HTMLInputElement).value).toBe('T1078, T1110');
    });

    test('sends nothing and says what is wrong when an identifier is not one', async () => {
      const s = server();
      const { wrapper } = await boot(s, path);
      await wrapper.get('#override-techniques').setValue(true);
      await wrapper.get('#techniques').setValue('T1078, nope');
      await submit(wrapper);
      expect(patches(s)).toHaveLength(0);
      expect(wrapper.get('#techniques-hint + [role=alert]').text()).toContain('nope');
    });

    test('sends the notes together with the overrides that changed, and nothing else', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => json(200, incident()) });
      const { wrapper } = await boot(s, path);
      await wrapper.get('#notes').setValue('Done.');
      await wrapper.get('#severity').setValue('low');
      await submit(wrapper);
      expect(patches(s).map((r) => r.body)).toEqual([{ notes: 'Done.', severity_override: 'low' }]);
    });

    test('says so when the server refuses', async () => {
      const s = server('admin', { [`PATCH ${detail}`]: () => failure(400, 'invalid_request') });
      const { wrapper } = await boot(s, path);
      await wrapper.get('#notes').setValue('x');
      await submit(wrapper);
      expect(wrapper.get('[role=alert]').text()).toBe('The input is not valid.');
      expect(wrapper.text()).not.toContain('Saved.');
    });

    test('shows the notes as text', async () => {
      const notes = '<img src=x onerror=alert(1)>';
      const { wrapper } = await boot(server('viewer', { [`GET ${detail}`]: () => json(200, incident({ notes })) }), path);
      expect(wrapper.find('img[src=x]').exists()).toBe(false);
      expect(wrapper.get('dd.notes').text()).toBe(notes);
    });
  });

  describe('for a viewer', () => {
    test('is read only: no button, no form, but the notes', async () => {
      const s = server('viewer', { [`GET ${detail}`]: () => json(200, incident({ notes: 'Checking fs01.' })) });
      const { wrapper } = await boot(s, path);
      expect(button(wrapper, 'Acknowledge')).toBeUndefined();
      expect(button(wrapper, 'Close')).toBeUndefined();
      expect(wrapper.find('form').exists()).toBe(false);
      expect(wrapper.get('dl').text()).toContain('Checking fs01.');
      expect(wrapper.text()).toContain('Events');
    });
  });

  describe('for a user', () => {
    test('triages, because the role may write incidents', async () => {
      const { wrapper } = await boot(server('user'), path);
      expect(button(wrapper, 'Acknowledge')).toBeDefined();
      expect(wrapper.find('form').exists()).toBe(true);
    });
  });
});

describe('the events of an incident', () => {
  const path = `/incidents/${incidentId}`;

  test('asks for the events of the incident and shows what happened', async () => {
    const s = server('admin', { 'GET /api/v1/events': () => json(200, { events: [event(), dnsEvent(), sensorEvent()] }) });
    const { wrapper } = await boot(s, path);
    expect(urls(s, '/api/v1/events')).toEqual([`/api/v1/events?limit=50&incident_id=${incidentId}`]);
    const rows = wrapper.findAll('.table tbody tr');
    expect(rows).toHaveLength(3);
    expect(rows[0]?.text()).toContain('GET');
    expect(rows[0]?.text()).toContain('curl/8.4.0');
    expect(rows[0]?.text()).toContain('Backup share link');
    expect(rows[1]?.text()).toContain('abcdefghijklmnopqrstuvwxyz');
    expect(rows[2]?.text()).toContain('SSH: Login attempt, root');
    expect(rows[2]?.text()).toContain('Jump host');
    expect(rows[0]?.get('a').attributes('href')).toBe(`/events/${eventId}`);
  });

  test('shows a session without attempts without a user name', async () => {
    const quiet = sensorEvent({ sensor: { ...sensorEvent().sensor!, event_type: 'connection', attempts: [] } });
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/events': () => json(200, { events: [quiet] }) }), path);
    expect(wrapper.get('.table tbody tr td:nth-child(2)').text()).toBe('SSH: Connection');
  });

  test('draws what the attacker sent as text, in its own direction', async () => {
    const hostile = event({ http: { method: 'GET', user_agent: '<img src=x onerror=alert(1)>\u05E9\u05DC\u05D5\u05DD', referer: '', accept_language: '', body_excerpt: '' } });
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/events': () => json(200, { events: [hostile] }) }), path);
    expect(wrapper.find('img[src=x]').exists()).toBe(false);
    expect(wrapper.get('.table tbody bdi').attributes('dir')).toBe('ltr');
    expect(wrapper.get('.table tbody bdi').text()).toBe('<img src=x onerror=alert(1)>\u05E9\u05DC\u05D5\u05DD');
  });

  test('says so when there are none, and when they cannot be loaded', async () => {
    const none = await boot(server('admin', { 'GET /api/v1/events': () => json(200, { events: [] }) }), path);
    expect(none.wrapper.text()).toContain('This incident has no events.');
    document.body.innerHTML = '';
    const failed = await boot(server('admin', { 'GET /api/v1/events': () => failure(500, 'internal_error') }), path);
    expect(failed.wrapper.text()).toContain('The events could not be loaded.');
  });

  test('says that events were deleted when the incident counts more than it lists', async () => {
    const { wrapper } = await boot(server('admin', { [`GET ${detail}`]: () => json(200, incident({ event_count: 9 })) }), path);
    expect(wrapper.text()).toContain('The incident counts 9 events. The others were deleted after the retention.');
  });

  test('does not say so while more pages wait', async () => {
    const s = server('admin', {
      [`GET ${detail}`]: () => json(200, incident({ event_count: 9 })),
      'GET /api/v1/events': () => json(200, { events: [event()], next_cursor: 'more' }),
    });
    const { wrapper } = await boot(s, path);
    expect(wrapper.text()).not.toContain('were deleted after the retention');
  });

  test('does not say so while the incident counts what it lists', async () => {
    const { wrapper } = await boot(server('admin', { [`GET ${detail}`]: () => json(200, incident({ event_count: 1 })) }), path);
    expect(wrapper.text()).not.toContain('were deleted after the retention');
  });

  test('reads the next page with the cursor', async () => {
    const s = server('admin', {
      'GET /api/v1/events': (r) => (r.url.includes('cursor=more') ? json(200, { events: [dnsEvent()] }) : json(200, { events: [event()], next_cursor: 'more' })),
    });
    const { wrapper } = await boot(s, path);
    await button(wrapper, 'Load more')!.trigger('click');
    await flushPromises();
    expect(wrapper.findAll('.table tbody tr')).toHaveLength(2);
    expect(urls(s, '/api/v1/events').at(-1)).toBe(`/api/v1/events?limit=50&cursor=more&incident_id=${incidentId}`);
  });

  test('are shown to a viewer, who reads events', async () => {
    const { wrapper } = await boot(server('viewer'), path);
    expect(wrapper.findAll('.table tbody tr')).toHaveLength(1);
  });
});

describe('an event', () => {
  const at = (id: string) => `/events/${id}`;

  function one(e: ReturnType<typeof event>, role: Role = 'admin') {
    return server(role, { [`GET /api/v1/events/${e.id}`]: () => json(200, e) });
  }

  test('shows a web request with the headers as text', async () => {
    const e = event({ http: { method: 'GET', user_agent: 'curl/8.4.0', referer: 'https://wiki.example.net/backups', accept_language: 'de-DE', body_excerpt: '' } });
    const { wrapper } = await boot(one(e), at(e.id));
    const text = wrapper.text();
    expect(text).toContain('Web request');
    expect(text).toContain('203.0.113.7');
    expect(text).toContain('curl/8.4.0');
    expect(text).toContain('https://wiki.example.net/backups');
    expect(text).toContain('de-DE');
    expect(text).toContain('Backup share link');
    expect(wrapper.find('dl a[href^="http"]').exists()).toBe(false);
  });

  test('links back to its incident', async () => {
    const { wrapper } = await boot(one(event()), at(eventId));
    expect(wrapper.get('p a').attributes('href')).toBe(`/incidents/${incidentId}`);
  });

  test('links to the list when it has no incident yet', async () => {
    const { wrapper } = await boot(one(event({ incident_id: null })), at(eventId));
    expect(wrapper.get('p a').attributes('href')).toBe('/incidents');
  });

  test('shows when it occurred only if that is not when it was recorded', async () => {
    const same = event({ occurred_at: '2026-10-22T07:00:05Z', recorded_at: '2026-10-22T07:00:05Z' });
    expect((await boot(one(same), at(same.id))).wrapper.text()).not.toContain('Occurred');
    document.body.innerHTML = '';
    const late = dnsEvent({ occurred_at: '2026-10-22T06:57:00Z' });
    expect((await boot(one(late), at(late.id))).wrapper.text()).toContain('Occurred');
  });

  test('shows a DNS query', async () => {
    const e = dnsEvent();
    const { wrapper } = await boot(one(e), at(e.id));
    const text = wrapper.text();
    expect(text).toContain('DNS query');
    expect(text).toContain('t.example.net');
    expect(text).toContain('abcdefghijklmnopqrstuvwxyz');
    expect(text).toContain('udp');
  });

  test('shows a session of a honeypot with its attempts and no password', async () => {
    const e = sensorEvent();
    const { wrapper } = await boot(one(e), at(e.id));
    const text = wrapper.text();
    expect(text).toContain('Honeypot session');
    expect(text).toContain('SSH');
    expect(text).toContain('SSH-2.0-libssh_0.9');
    expect(text).toContain('4.2 s');
    const rows = wrapper.findAll('.table tbody tr');
    expect(rows).toHaveLength(2);
    expect(rows[0]?.text()).toContain('root');
    expect(rows[0]?.text()).toContain('8 characters');
    expect(rows[1]?.text()).toContain('admin');
    expect(rows[1]?.text()).toContain('SHA256:abc');
    expect(rows[0]?.findAll('td')[1]?.text()).toBe('8 characters');
    expect(rows[1]?.findAll('td')[1]?.text()).toBe('None');
  });

  test('shows the database, the application and the search of a session', async () => {
    const e = sensorEvent({
      sensor: {
        service: 'ldap',
        event_type: 'directory_query',
        port: 389,
        duration_ms: 100,
        client_version: null,
        database: 'prod',
        application_name: 'psql',
        query: { base_dn: 'dc=example,dc=net', filter: '(objectClass=*)' },
        attempts: [],
      },
    });
    const { wrapper } = await boot(one(e), at(e.id));
    const text = wrapper.text();
    expect(text).toContain('prod');
    expect(text).toContain('psql');
    expect(text).toContain('dc=example,dc=net');
    expect(text).toContain('(objectClass=*)');
    expect(wrapper.find('.table').exists()).toBe(false);
  });

  test('leaves out the members that the session does not have', async () => {
    const e = sensorEvent({ sensor: { ...sensorEvent().sensor!, client_version: null } });
    const { wrapper } = await boot(one(e), at(e.id));
    for (const label of ['Database', 'Application name', 'Search base', 'Search filter', 'Client version']) {
      expect(wrapper.text()).not.toContain(label);
    }
  });

  test.each([
    ['the user agent', event({ http: { method: 'GET', user_agent: '<script>alert(1)</script>', referer: '', accept_language: '', body_excerpt: '' } })],
    ['the body of a POST request', event({ http: { method: 'POST', user_agent: '', referer: '', accept_language: '', body_excerpt: '<script>alert(1)</script>' } })],
    ['a user name', sensorEvent({ sensor: { ...sensorEvent().sensor!, attempts: [{ username: '<script>alert(1)</script>', password_length: null, key_fingerprint: null }] } })],
    ['the search filter', sensorEvent({ sensor: { ...sensorEvent().sensor!, query: { base_dn: '<script>alert(1)</script>', filter: '<script>alert(1)</script>' } } })],
    ['the name before the zone', dnsEvent({ dns: { zone: 'z', prefix: '<script>alert(1)</script>', qtype: 'A', transport: 'tcp' } })],
  ])('draws %s as text', async (_, e) => {
    const { wrapper } = await boot(one(e), at(e.id));
    expect(wrapper.find('script').exists()).toBe(false);
    expect(wrapper.text()).toContain('<script>alert(1)</script>');
  });

  test('marks a character that shows nothing, and isolates the direction of a value', async () => {
    const e = event({ http: { method: 'GET', user_agent: `agent\u3164\u202E\u05E9`, referer: '', accept_language: '', body_excerpt: '' } });
    const { wrapper } = await boot(one(e), at(e.id));
    const markers = wrapper.findAll('.marker').map((m) => m.text());
    expect(markers).toEqual(['\u2039U+3164\u203A', '\u2039U+202E\u203A']);
    for (const bdi of wrapper.findAll('bdi.untrusted')) {
      expect(bdi.attributes('dir')).toBe('ltr');
    }
  });

  test('shows the start of the body for a POST request only', async () => {
    const post = event({ http: { method: 'POST', user_agent: '', referer: '', accept_language: '', body_excerpt: 'user=alice' } });
    const shown = await boot(one(post), at(post.id));
    expect(shown.wrapper.text()).toContain('Start of the body');
    expect(shown.wrapper.text()).toContain('user=alice');
    document.body.innerHTML = '';
    const hidden = await boot(one(event()), at(eventId));
    expect(hidden.wrapper.text()).not.toContain('Start of the body');
  });

  test('says that a value is empty', async () => {
    const { wrapper } = await boot(one(event()), at(eventId));
    expect(wrapper.text()).toContain('(empty)');
  });

  test('draws every value of an attacker in an element that isolates it, and in no attribute', async () => {
    const e = sensorEvent();
    const { wrapper } = await boot(one(e), at(e.id));
    expect(wrapper.findAll('bdi.untrusted').length).toBeGreaterThanOrEqual(4);
    for (const element of [...wrapper.element.querySelectorAll('*')]) {
      for (const attribute of element.getAttributeNames()) {
        expect(element.getAttribute(attribute) ?? '', `${element.tagName} ${attribute}`).not.toContain('libssh');
      }
    }
  });

  test('is shown to a viewer', async () => {
    const { wrapper } = await boot(one(event(), 'viewer'), at(eventId));
    expect(wrapper.get('h1').text()).toBe('Event');
  });

  test('says when it does not exist', async () => {
    const { wrapper } = await boot(server('admin', { [`GET /api/v1/events/${eventId}`]: () => failure(404, 'not_found') }), at(eventId));
    expect(wrapper.text()).toContain('Nothing found here.');
  });

  test('says when it cannot be loaded', async () => {
    const { wrapper } = await boot(server('admin', { [`GET /api/v1/events/${eventId}`]: () => failure(500, 'internal_error') }), at(eventId));
    expect(wrapper.get('[role=alert]').text()).toBe('Something went wrong on the server.');
  });
});

describe('the pages in German', () => {
  test('speak German and keep the values as they are', async () => {
    const { wrapper, i18n } = await boot(server(), `/incidents/${incidentId}`);
    i18n.setLocale('de');
    await flushPromises();
    expect(wrapper.text()).toContain('Triage');
    expect(wrapper.text()).toContain('Inhalt');
    expect(wrapper.text()).toContain('curl/8.4.0');
  });
});
