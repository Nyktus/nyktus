// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises } from '@vue/test-utils';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { boot } from './testing/boot';
import { failure, fakeServer, honeypot, honeypotId, honeytoken, incident, incidentId, json, sessionBody, type Handler } from './testing/fakeServer';
import {
  countLabel,
  listedHoneypots,
  listedIncidents,
  summarizeHoneypots,
  summarizeHoneytokens,
  summarizeIncidents,
} from './overview';

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  document.body.innerHTML = '';
  history.replaceState(null, '', '/');
});

const page = <T>(items: T[], more = false) => ({ items, more });
const uuid = (n: number): string => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;

describe('countLabel', () => {
  test('is the number, or a lower bound when the list goes on', () => {
    expect(countLabel(12, false)).toBe('12');
    expect(countLabel(200, true)).toBe('200+');
    expect(countLabel(1200, true, (n) => n.toLocaleString('de'))).toBe('1.200+');
  });
});

describe('summarizeIncidents', () => {
  test('counts what is open and what is acknowledged, and leaves out what is closed', () => {
    const summary = summarizeIncidents(
      page([incident({ id: uuid(1) }), incident({ id: uuid(2), status: 'acknowledged' }), incident({ id: uuid(3), status: 'closed' }), incident({ id: uuid(4) })]),
    );
    expect([summary.open, summary.acknowledged]).toEqual([2, 1]);
    expect(summary.lead.map((i) => i.id)).not.toContain(uuid(3));
  });

  test('puts the open before the acknowledged, the more severe first, and keeps the order of the server among equals', () => {
    const summary = summarizeIncidents(
      page([
        incident({ id: uuid(1), status: 'acknowledged', severity: 'critical' }),
        incident({ id: uuid(2), severity: 'low' }),
        incident({ id: uuid(3), severity: 'critical' }),
        incident({ id: uuid(4), severity: 'low' }),
      ]),
    );
    expect(summary.lead.map((i) => i.id)).toEqual([uuid(3), uuid(2), uuid(4), uuid(1)]);
  });

  test('lists only the first few', () => {
    const many = Array.from({ length: listedIncidents + 3 }, (_, i) => incident({ id: uuid(i + 1) }));
    const summary = summarizeIncidents(page(many));
    expect(summary.lead).toHaveLength(listedIncidents);
    expect(summary.open).toBe(listedIncidents + 3);
  });

  test('passes on that the list goes on', () => {
    expect(summarizeIncidents(page([], true)).more).toBe(true);
  });
});

describe('summarizeHoneypots', () => {
  test('counts the enabled ones by status and the disabled ones apart', () => {
    const summary = summarizeHoneypots(
      page([
        honeypot({ id: uuid(1), status: 'online' }),
        honeypot({ id: uuid(2), status: 'offline' }),
        honeypot({ id: uuid(3), status: 'never' }),
        honeypot({ id: uuid(4), status: 'offline', enabled: false }),
      ]),
    );
    expect([summary.online, summary.offline, summary.never, summary.disabled]).toEqual([1, 1, 1, 1]);
  });

  test('does not call a disabled honeypot that is silent a fault', () => {
    const summary = summarizeHoneypots(page([honeypot({ status: 'offline', enabled: false }), honeypot({ id: uuid(2), status: 'never', enabled: false })]));
    expect(summary.silent).toEqual([]);
    expect(summary.offline + summary.never).toBe(0);
  });

  test('names the ones that stopped before the ones that never began', () => {
    const summary = summarizeHoneypots(
      page([honeypot({ id: uuid(1), status: 'never' }), honeypot({ id: uuid(2), status: 'online' }), honeypot({ id: uuid(3), status: 'offline' })]),
    );
    expect(summary.silent.map((h) => h.id)).toEqual([uuid(3), uuid(1)]);
  });

  test('names only the first few', () => {
    const many = Array.from({ length: listedHoneypots + 2 }, (_, i) => honeypot({ id: uuid(i + 1), status: 'offline' }));
    expect(summarizeHoneypots(page(many)).silent).toHaveLength(listedHoneypots);
    expect(summarizeHoneypots(page(many)).offline).toBe(listedHoneypots + 2);
  });
});

describe('summarizeHoneytokens', () => {
  test('counts the active ones by type in a fixed order, and leaves out a type that has none', () => {
    const summary = summarizeHoneytokens(
      page([
        honeytoken({ id: uuid(1), type: 'dns' }),
        honeytoken({ id: uuid(2), type: 'web_url' }),
        honeytoken({ id: uuid(3), type: 'dns' }),
        honeytoken({ id: uuid(4), type: 'web_image', enabled: false }),
      ]),
    );
    expect(summary.byType).toEqual([
      { type: 'web_url', count: 1 },
      { type: 'dns', count: 2 },
    ]);
    expect([summary.active, summary.disabled]).toEqual([3, 1]);
  });
});

type Role = 'admin' | 'user' | 'viewer';

const activeIncidents = '/api/v1/incidents?limit=200&status=open%2Cacknowledged';

function server(role: Role = 'admin', extra: Record<string, Handler> = {}) {
  return fakeServer({
    'GET /api/v1/session': () => json(200, sessionBody(role)),
    'GET /api/v1/incidents': () => json(200, { incidents: [incident()] }),
    'GET /api/v1/honeypots': () => json(200, { honeypots: [honeypot()] }),
    'GET /api/v1/honeytokens': () => json(200, { honeytokens: [honeytoken()] }),
    ...extra,
  });
}

const urls = (s: ReturnType<typeof server>, prefix: string): string[] => s.requests.map((r) => r.url).filter((u) => u.startsWith(prefix));
const tile = (wrapper: Awaited<ReturnType<typeof boot>>['wrapper'], title: string) => wrapper.findAll('.tile').find((t) => t.get('h2').text() === title)!;

describe('the overview', () => {
  test('asks for the lists once, a page of the most the server gives, and for the open incidents only', async () => {
    const s = server();
    await boot(s, '/');
    expect(urls(s, '/api/v1/incidents')).toEqual([activeIncidents]);
    expect(urls(s, '/api/v1/honeypots')).toEqual(['/api/v1/honeypots?limit=200']);
    expect(urls(s, '/api/v1/honeytokens')).toEqual(['/api/v1/honeytokens?limit=200']);
  });

  test('has no sentence about the state, only the link to the documentation', async () => {
    const { wrapper } = await boot(server(), '/');
    expect(wrapper.findAll('.page-head .lede')).toHaveLength(1);
    expect(wrapper.get('.page-head .lede a').attributes('href')).toBe('https://docs.nyktus.org');
  });

  test('has no language choice and no copy of the account: those are in the frame and on the account page', async () => {
    const { wrapper } = await boot(server(), '/');
    expect(wrapper.find('main select').exists()).toBe(false);
    expect(wrapper.get('main').text()).not.toContain('Signed in as');
  });

  describe('the incidents', () => {
    test('are counted by status and listed, each with a link to the incident', async () => {
      const ack = incident({ id: 'f00dfeed-2222-4222-8333-944444444444', status: 'acknowledged', resource_name: 'Jump host', resource_type: 'honeypot', severity: 'medium' });
      const { wrapper } = await boot(server('admin', { 'GET /api/v1/incidents': () => json(200, { incidents: [incident(), ack] }) }), '/');
      const t = tile(wrapper, 'Incidents');
      expect(t.findAll('.count').map((c) => c.text())).toEqual(['Open1', 'Acknowledged1']);
      const rows = t.findAll('.row');
      expect(rows.map((r) => r.get('a').text())).toEqual(['Stolen backup', 'Jump host']);
      expect(rows[0]!.get('a').attributes('href')).toBe(`/incidents/${incidentId}`);
      expect(rows[0]!.text()).toContain('High');
      expect(rows[0]!.text()).toContain('Scenario');
      expect(rows[1]!.text()).toContain('Acknowledged');
      expect(rows[0]!.text(), 'an open incident needs no status next to it').not.toContain('Open');
    });

    test('mark the figure of the open ones when some are open, and only then', async () => {
      const open = await boot(server(), '/');
      expect(tile(open.wrapper, 'Incidents').get('.count').classes()).toContain('alarm');
      document.body.innerHTML = '';
      const none = await boot(server('admin', { 'GET /api/v1/incidents': () => json(200, { incidents: [] }) }), '/');
      expect(tile(none.wrapper, 'Incidents').get('.count').classes()).not.toContain('alarm');
    });

    test('say so when there are none, without saying that nothing is wrong', async () => {
      const { wrapper } = await boot(server('admin', { 'GET /api/v1/incidents': () => json(200, { incidents: [] }) }), '/');
      const t = tile(wrapper, 'Incidents');
      expect(t.text()).toContain('No unprocessed incidents.');
      expect(wrapper.text()).not.toMatch(/\b(safe|secure|all clear)\b/i);
    });

    test('are shown as a lower bound when the server has more than the page', async () => {
      const { wrapper } = await boot(server('admin', { 'GET /api/v1/incidents': () => json(200, { incidents: [incident()], next_cursor: 'more' }) }), '/');
      expect(tile(wrapper, 'Incidents').findAll('.count').map((c) => c.text())).toEqual(['Open1+', 'Acknowledged0+']);
      expect(tile(wrapper, 'Incidents').text()).toContain('The incident list is limited. Use the filter to narrow the selection.');
    });

    test('say nothing of more incidents when the page holds them all', async () => {
      const { wrapper } = await boot(server(), '/');
      expect(tile(wrapper, 'Incidents').text()).not.toContain('more incidents than');
    });

    test('show a name that is markup as text', async () => {
      const hostile = incident({ resource_name: '<img src=x onerror=alert(1)>' });
      const { wrapper } = await boot(server('admin', { 'GET /api/v1/incidents': () => json(200, { incidents: [hostile] }) }), '/');
      expect(wrapper.find('img[src=x]').exists()).toBe(false);
      expect(tile(wrapper, 'Incidents').get('.row a').text()).toBe('<img src=x onerror=alert(1)>');
    });

    test('link to the whole list', async () => {
      const { wrapper } = await boot(server(), '/');
      expect(tile(wrapper, 'Incidents').get('.tile-head a').attributes('href')).toBe('/incidents');
    });
  });

  describe('the honeypots', () => {
    test('are counted by status, and the ones that do not report are named', async () => {
      const gone = honeypot({ id: honeypotId, name: 'Jump host', status: 'offline', last_seen_at: '2026-10-22T07:55:00Z' });
      const fresh = honeypot({ id: 'c0ffee00-2222-4222-8333-944444444444', name: 'Wiki DB', service: 'postgres', status: 'never', last_seen_at: null });
      const fine = honeypot({ id: 'c0ffee00-3333-4222-8333-944444444444', name: 'Router', service: 'telnet', status: 'online' });
      const none = { 'GET /api/v1/incidents': () => json(200, { incidents: [] }) };
      const { wrapper } = await boot(server('admin', { ...none, 'GET /api/v1/honeypots': () => json(200, { honeypots: [fine, fresh, gone] }) }), '/');
      const t = tile(wrapper, 'Honeypots');
      expect(t.findAll('.count').map((c) => c.text())).toEqual(['Online1', 'Offline1', 'No report1']);
      expect(t.findAll('.count')[1]!.classes()).toContain('alarm');
      expect(t.findAll('.row').map((r) => r.get('a').text())).toEqual(['Jump host', 'Wiki DB']);
      expect(t.findAll('.row')[0]!.get('a').attributes('href')).toBe(`/honeypots/${honeypotId}`);
      expect(t.findAll('.row')[0]!.text()).toContain('Offline');
      expect(t.findAll('.row')[1]!.text()).toContain('No report yet');
    });

    test('count a disabled one apart and do not name it', async () => {
      const off = honeypot({ enabled: false, status: 'offline' });
      const { wrapper } = await boot(server('admin', { 'GET /api/v1/honeypots': () => json(200, { honeypots: [off] }) }), '/');
      const t = tile(wrapper, 'Honeypots');
      expect(t.findAll('.count').map((c) => c.text())).toEqual(['Online0', 'Offline0', 'No report0', 'Disabled1']);
      expect(t.find('.rows').exists()).toBe(false);
      expect(t.findAll('.count').some((c) => c.classes().includes('alarm'))).toBe(false);
    });

    test('teach what to do when there are none, with the action for a role that may create one', async () => {
      const empty = { 'GET /api/v1/honeypots': () => json(200, { honeypots: [] }) };
      const admin = await boot(server('admin', empty), '/');
      expect(tile(admin.wrapper, 'Honeypots').text()).toContain('No honeypot is set up.');
      expect(tile(admin.wrapper, 'Honeypots').get('a.button').attributes('href')).toBe('/honeypots/new');
      document.body.innerHTML = '';
      const viewer = await boot(server('viewer', empty), '/');
      expect(tile(viewer.wrapper, 'Honeypots').text()).toContain('No honeypot is set up.');
      expect(tile(viewer.wrapper, 'Honeypots').find('a.button').exists()).toBe(false);
    });
  });

  describe('the honeytokens', () => {
    test('are counted as active and disabled, with the active ones by type', async () => {
      const list = [
        honeytoken({ id: 'c0ffee00-0001-4222-8333-944444444444' }),
        honeytoken({ id: 'c0ffee00-0002-4222-8333-944444444444', type: 'dns' }),
        honeytoken({ id: 'c0ffee00-0003-4222-8333-944444444444', type: 'dns', enabled: false }),
      ];
      const { wrapper } = await boot(server('admin', { 'GET /api/v1/honeytokens': () => json(200, { honeytokens: list }) }), '/');
      const t = tile(wrapper, 'Honeytokens');
      expect(t.findAll('.count').map((c) => c.text())).toEqual(['Active2', 'Disabled1']);
      expect(t.findAll('.types li').map((li) => li.text())).toEqual(['Web URL 1', 'DNS name 1']);
    });

    test('teach what to do when there are none, and lead to the catalog first', async () => {
      const { wrapper } = await boot(server('admin', { 'GET /api/v1/honeytokens': () => json(200, { honeytokens: [] }) }), '/');
      const t = tile(wrapper, 'Honeytokens');
      expect(t.text()).toContain('No honeytoken is set up.');
      expect(t.findAll('a.button').map((a) => [a.text(), a.attributes('href')])).toEqual([
        ['Apply a deception', '/catalog'],
        ['New honeytoken', '/honeytokens/new'],
      ]);
    });
  });

  describe('when a list cannot be read', () => {
    test('the others are still shown, and the tile says that it failed', async () => {
      const { wrapper } = await boot(server('admin', { 'GET /api/v1/honeypots': () => failure(500, 'internal_error') }), '/');
      expect(tile(wrapper, 'Honeypots').get('[role=alert]').text()).toBe('Loading failed. Try again.');
      expect(tile(wrapper, 'Incidents').find('[role=alert]').exists()).toBe(false);
      expect(tile(wrapper, 'Incidents').findAll('.count')).toHaveLength(2);
      expect(tile(wrapper, 'Honeytokens').findAll('.count')).toHaveLength(2);
    });

    test('says that the incidents could not be read, and still shows the page', async () => {
      const { wrapper } = await boot(server('admin', { 'GET /api/v1/incidents': () => failure(500, 'internal_error') }), '/');
      expect(wrapper.get('h1').text()).toBe('Overview');
      expect(tile(wrapper, 'Incidents').find('[role=alert]').exists()).toBe(true);
    });

    test('the server message never reaches the page', async () => {
      const { wrapper } = await boot(server('admin', { 'GET /api/v1/incidents': () => failure(500, 'internal_error') }), '/');
      expect(wrapper.text()).not.toContain('message that the console must never show');
    });
  });

  describe('refreshing', () => {
    test('asks the three lists again on request, and keeps what it showed while it waits', async () => {
      const s = server();
      const { wrapper } = await boot(s, '/');
      await wrapper.get('.page-head button').trigger('click');
      await flushPromises();
      expect(urls(s, '/api/v1/incidents')).toHaveLength(2);
      expect(urls(s, '/api/v1/honeypots')).toHaveLength(2);
      expect(urls(s, '/api/v1/honeytokens')).toHaveLength(2);
    });

    test('shows a new incident that the next look finds, and keeps the old figures when the look fails', async () => {
      let answer: () => Response = () => json(200, { incidents: [incident()] });
      const s = server('admin', { 'GET /api/v1/incidents': () => answer() });
      const { wrapper } = await boot(s, '/');
      expect(tile(wrapper, 'Incidents').findAll('.count')[0]!.text()).toBe('Open1');
      answer = () => failure(500, 'internal_error');
      await wrapper.get('.page-head button').trigger('click');
      await flushPromises();
      expect(tile(wrapper, 'Incidents').findAll('.count')[0]!.text()).toBe('Open1');
      const incidents = tile(wrapper, 'Incidents');
      expect(incidents.find('[role=alert]').exists(), 'a failed look is no reason to hide what is known').toBe(false);
      expect(incidents.get('[role=status]').text()).toBe('Refreshing failed. The data may be out of date.');
      expect(tile(wrapper, 'Honeypots').find('.notice').exists(), 'only the tile that failed says so').toBe(false);
      answer = () => json(200, { incidents: [incident(), incident({ id: 'f00dfeed-2222-4222-8333-944444444444' })] });
      await wrapper.get('.page-head button').trigger('click');
      await flushPromises();
      expect(tile(wrapper, 'Incidents').find('.notice').exists(), 'the note goes when the next look succeeds').toBe(false);
      expect(tile(wrapper, 'Incidents').findAll('.count')[0]!.text()).toBe('Open2');
    });

    test('does not start a second look while one is on its way', async () => {
      let release: () => void = () => {};
      const slow = new Promise<void>((resolve) => {
        release = resolve;
      });
      const s = server('admin', {
        'GET /api/v1/honeypots': async () => {
          await slow;
          return json(200, { honeypots: [honeypot()] });
        },
      });
      const { wrapper } = await boot(s, '/');
      expect(wrapper.get('.page-head button').attributes('disabled')).toBeDefined();
      await wrapper.get('.page-head button').trigger('click');
      release();
      await flushPromises();
      expect(urls(s, '/api/v1/honeypots')).toHaveLength(1);
      expect(wrapper.get('.page-head button').attributes('disabled')).toBeUndefined();
    });

    describe('on its own', () => {
      test('looks again every minute while the page is visible', async () => {
        vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
        const s = server();
        await boot(s, '/');
        await vi.advanceTimersByTimeAsync(60_000);
        await flushPromises();
        expect(urls(s, '/api/v1/incidents')).toHaveLength(2);
      });

      test('does not look while the page is hidden', async () => {
        vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
        Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });
        try {
          const s = server();
          await boot(s, '/');
          await vi.advanceTimersByTimeAsync(180_000);
          await flushPromises();
          expect(urls(s, '/api/v1/incidents')).toHaveLength(1);
        } finally {
          Reflect.deleteProperty(document, 'visibilityState');
        }
      });

      test('stops when the user leaves the page', async () => {
        vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
        const s = server();
        const { router } = await boot(s, '/');
        await router.push('/forbidden');
        await flushPromises();
        const before = urls(s, '/api/v1/incidents').length;
        await vi.advanceTimersByTimeAsync(300_000);
        await flushPromises();
        expect(urls(s, '/api/v1/incidents')).toHaveLength(before);
      });
    });
  });
});
