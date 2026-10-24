// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises } from '@vue/test-utils';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { arrive, boot } from './testing/boot';
import { auditEntry, failure, fakeServer, json, metricsText, plain, sessionBody, type Handler } from './testing/fakeServer';

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = '';
  history.replaceState(null, '', '/');
});

type Role = 'admin' | 'user' | 'viewer';
type Wrapper = Awaited<ReturnType<typeof boot>>['wrapper'];

function server(role: Role = 'admin', extra: Record<string, Handler> = {}) {
  return fakeServer({
    'GET /api/v1/session': () => json(200, sessionBody(role)),
    'GET /api/v1/audit-entries': () => json(200, { entries: [auditEntry()] }),
    'GET /api/v1/metrics': () => plain(200, metricsText),
    ...extra,
  });
}

const button = (wrapper: Wrapper, label: string) => wrapper.findAll('button').find((b) => b.text() === label);

describe('the audit log', () => {
  test('shows each entry with its time, action, result, actor, resource and changed fields', async () => {
    const { wrapper } = await boot(server(), '/audit');
    const row = wrapper.get('tbody tr');
    expect(row.get('time').attributes('datetime')).toBe('2026-10-23T09:00:00Z');
    expect(row.text()).toContain('honeytoken.update');
    expect(row.text()).toContain('req-1234');
    expect(row.text()).toContain('Success');
    expect(row.text()).toContain('Ada Admin');
    expect(row.text()).toContain('ada@example.com');
    expect(row.text()).toContain('Account, session');
    expect(row.text()).toContain('honeytoken');
    expect(row.text()).toContain('name, notes');
    expect(row.text()).toContain('203.0.113.9');
  });

  test('links a resource to its page, where the console has one, by its identifier', async () => {
    const { wrapper } = await boot(server(), '/audit');
    expect(wrapper.get('tbody tr .resource a').attributes('href')).toBe('/honeytokens/c0ffee00-1111-4222-8333-944444444444');
    expect(wrapper.get('tbody tr .resource a').text()).toBe('c0ffee00-1111-4222-8333-944444444444');
  });

  test.each([
    ['user', '/users/'],
    ['honeypot', '/honeypots/'],
    ['scenario', '/scenarios/'],
    ['artifact', '/artifacts/'],
    ['alert_channel', '/alert-channels/'],
    ['incident', '/incidents/'],
  ])('links a resource of the type %s to %s', async (type, prefix) => {
    const entry = auditEntry({ resource: { type, id: '11111111-1111-4222-8333-944444444444' } });
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/audit-entries': () => json(200, { entries: [entry] }) }), '/audit');
    expect(wrapper.get('tbody .resource a').attributes('href')).toBe(`${prefix}11111111-1111-4222-8333-944444444444`);
  });

  // What an entry records as deleted has no page to go to.
  test.each([
    ['honeytoken.delete', 'honeytoken'],
    ['scenario.delete', 'scenario'],
    ['user.delete', 'user'],
    ['artifact.delete', 'artifact'],
  ])('shows the resource of %s by its identifier only, without a link', async (action, type) => {
    const entry = auditEntry({ action, resource: { type, id: '11111111-1111-4222-8333-944444444444' } });
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/audit-entries': () => json(200, { entries: [entry] }) }), '/audit');
    expect(wrapper.find('tbody .resource a').exists()).toBe(false);
    expect(wrapper.get('tbody .resource').text()).toContain('11111111-1111-4222-8333-944444444444');
  });

  test('shows the address of an actor as text, apart from the name', async () => {
    const entry = auditEntry({ actor: { kind: 'user', auth_method: 'session', display_name: 'A\u202Eb', email: 'x\u202Ey@example.com' } });
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/audit-entries': () => json(200, { entries: [entry] }) }), '/audit');
    expect(wrapper.findAll('tbody .actor bdi')).toHaveLength(2);
    expect(wrapper.get('tbody .actor .email').element.tagName).toBe('BDI');
  });

  test('shows a resource of another type, or one that has no page, by type and identifier only', async () => {
    const entry = auditEntry({ resource: { type: 'api_key', id: '22222222-1111-4222-8333-944444444444' } });
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/audit-entries': () => json(200, { entries: [entry] }) }), '/audit');
    expect(wrapper.find('tbody .resource a').exists()).toBe(false);
    expect(wrapper.get('tbody .resource').text()).toBe('api_key22222222-1111-4222-8333-944444444444');
  });

  test('shows an entry without a resource, a field or an address', async () => {
    const entry = auditEntry({ action: 'session.create', resource: undefined, changed_fields: [], client_ip: undefined, request_id: undefined });
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/audit-entries': () => json(200, { entries: [entry] }) }), '/audit');
    const cells = wrapper.findAll('tbody td');
    expect(cells[4]?.text()).toBe('None');
    expect(cells[5]?.text()).toBe('None');
    expect(cells[6]?.text()).toBe('None');
    expect(wrapper.find('.request').exists()).toBe(false);
  });

  test('marks a failure and a denial, and names an actor that is no account', async () => {
    const failed = auditEntry({ id: '0d17e000-2222-4222-8333-944444444444', outcome: 'failure', actor: { kind: 'anonymous', auth_method: 'none' } });
    const denied = auditEntry({ id: '0d17e000-3333-4222-8333-944444444444', outcome: 'denied', actor: { kind: 'api_key', auth_method: 'api_key', display_name: 'SIEM export' } });
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/audit-entries': () => json(200, { entries: [auditEntry(), failed, denied] }) }), '/audit');
    const rows = wrapper.findAll('tbody tr');
    expect(rows[0]?.get('.badge').classes()).not.toContain('badge-strong');
    expect(rows[1]?.get('.badge').classes()).toContain('badge-strong');
    expect(rows[1]?.text()).toContain('Failed');
    expect(rows[1]?.text()).toContain('Anonymous, none');
    expect(rows[2]?.get('.badge').classes()).toContain('badge-muted');
    expect(rows[2]?.text()).toContain('Denied');
    expect(rows[2]?.text()).toContain('API key, API key');
    expect(rows[2]?.text()).toContain('SIEM export');
  });

  test('shows names that are markup as text', async () => {
    const entry = auditEntry({ actor: { kind: 'user', auth_method: 'oidc', email: 'a@example.com', display_name: '<img src=x onerror=alert(1)>' } });
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/audit-entries': () => json(200, { entries: [entry] }) }), '/audit');
    expect(wrapper.find('img[src=x]').exists()).toBe(false);
    expect(wrapper.get('tbody .actor bdi').text()).toBe('<img src=x onerror=alert(1)>');
  });

  test('reads the next page with the cursor, and the same list again on request', async () => {
    const second = auditEntry({ id: '0d17e000-4444-4222-8333-944444444444', action: 'user.create' });
    const s = server('admin', {
      'GET /api/v1/audit-entries': (r) => (r.url.includes('cursor=more') ? json(200, { entries: [second] }) : json(200, { entries: [auditEntry()], next_cursor: 'more' })),
    });
    const { wrapper } = await boot(s, '/audit');
    await button(wrapper, 'Load more')!.trigger('click');
    await flushPromises();
    expect(wrapper.findAll('tbody tr')).toHaveLength(2);
    expect(s.requests.at(-1)?.url).toBe('/api/v1/audit-entries?limit=50&cursor=more');
    await button(wrapper, 'Refresh')!.trigger('click');
    await flushPromises();
    expect(wrapper.findAll('tbody tr')).toHaveLength(1);
  });

  test('says that reading it is recorded, and what it is when there is nothing', async () => {
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/audit-entries': () => json(200, { entries: [] }) }), '/audit');
    expect(wrapper.text()).toContain('Reading the audit log is itself recorded.');
    expect(wrapper.text()).toContain('There are no entries.');
  });

  test('says so when it cannot be loaded', async () => {
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/audit-entries': () => failure(500, 'internal_error') }), '/audit');
    expect(wrapper.get('[role=alert]').text()).toContain('The audit log could not be loaded.');
  });
});

describe('the metrics', () => {
  test('shows each family with its help, labels and values', async () => {
    const { wrapper } = await boot(server(), '/metrics');
    const families = wrapper.findAll('.family');
    expect(families.map((f) => f.get('h2').text())).toEqual(['nyktus_event_jobs', 'nyktus_incidents', 'nyktus_periodic_task_last_success_timestamp_seconds']);
    expect(families[0]?.text()).toContain('Jobs of events that wait to be processed.');
    expect(families[0]?.get('tbody').text()).toContain('None');
    expect(families[0]?.get('tbody').text()).toContain('3');
    const rows = families[1]!.findAll('tbody tr');
    expect(rows).toHaveLength(2);
    expect(rows[0]?.text()).toContain('status: open');
    expect(rows[0]?.text()).toContain('2');
    expect(rows[1]?.text()).toContain('status: acknowledged');
  });

  test('shows a time next to the value of a metric that is one', async () => {
    const { wrapper } = await boot(server(), '/metrics');
    const row = wrapper.findAll('.family')[2]!.get('tbody tr');
    expect(row.text()).toContain('task: delete_expired_sign_in_data');
    expect(row.text()).toContain('1792746000');
    expect(row.get('time').attributes('datetime')).toBe('2026-10-23T09:00:00.000Z');
  });

  test('shows no time for a task that never ran, which reports zero', async () => {
    const never = '# TYPE nyktus_periodic_task_last_failure_timestamp_seconds gauge\nnyktus_periodic_task_last_failure_timestamp_seconds{task="x"} 0\n';
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/metrics': () => plain(200, never) }), '/metrics');
    expect(wrapper.get('tbody').text()).toContain('0');
    expect(wrapper.find('tbody time').exists()).toBe(false);
  });

  test('shows no time for a value that is not one', async () => {
    const { wrapper } = await boot(server(), '/metrics');
    expect(wrapper.findAll('.family')[0]!.find('time').exists()).toBe(false);
  });

  test('shows the families only, and no copy of the text', async () => {
    const { wrapper } = await boot(server(), '/metrics');
    expect(wrapper.find('details').exists()).toBe(false);
    expect(wrapper.find('pre').exists()).toBe(false);
  });

  test('says that a family without a value reported none, instead of showing an empty table', async () => {
    const text = '# HELP nyktus_incidents Incidents that are not closed.\n# TYPE nyktus_incidents gauge\n';
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/metrics': () => plain(200, text) }), '/metrics');
    expect(wrapper.get('.family tbody').text()).toBe('No value was reported.');
  });

  test('reads a text with the line ends of Windows', async () => {
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/metrics': () => plain(200, metricsText.replaceAll('\n', '\r\n')) }), '/metrics');
    expect(wrapper.findAll('.family')).toHaveLength(3);
  });

  test('has a button for another reading that does not borrow its name from the incidents', async () => {
    const { wrapper } = await boot(server(), '/metrics');
    expect(button(wrapper, 'Refresh')).toBeDefined();
    const audit = await boot(server(), '/audit');
    expect(button(audit.wrapper, 'Refresh')).toBeDefined();
  });

  test('draws help and labels as text, and leaves lines that it does not understand out', async () => {
    const hostile = '# HELP a <img src=x onerror=alert(1)>\n# TYPE a gauge\na{k="<b>x</b>"} 1\n<img src=x onerror=alert(2)>\n';
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/metrics': () => plain(200, hostile) }), '/metrics');
    expect(wrapper.find('img[src=x]').exists()).toBe(false);
    expect(wrapper.find('.family b').exists()).toBe(false);
    expect(wrapper.get('.family').text()).toContain('<img src=x onerror=alert(1)>');
    expect(wrapper.get('.family').text()).toContain('k: <b>x</b>');
    expect(wrapper.text()).not.toContain('onerror=alert(2)');
  });

  test('reads again on request, and shows the new values', async () => {
    let value = '3';
    const s = server('admin', { 'GET /api/v1/metrics': () => plain(200, `# TYPE nyktus_event_jobs gauge\nnyktus_event_jobs ${value}\n`) });
    const { wrapper } = await boot(s, '/metrics');
    expect(wrapper.get('tbody').text()).toContain('3');
    value = '9';
    await button(wrapper, 'Refresh')!.trigger('click');
    await flushPromises();
    expect(wrapper.get('tbody').text()).toContain('9');
    expect(s.requests.filter((r) => r.url === '/api/v1/metrics')).toHaveLength(2);
  });

  test('keeps the old values and says so when a new reading fails', async () => {
    let fail = false;
    const s = server('admin', { 'GET /api/v1/metrics': () => (fail ? failure(503, 'unavailable') : plain(200, metricsText)) });
    const { wrapper } = await boot(s, '/metrics');
    fail = true;
    await button(wrapper, 'Refresh')!.trigger('click');
    await flushPromises();
    expect(wrapper.get('[role=alert]').text()).toBe('The metrics could not be loaded. The server is busy. Try again in a moment.');
    expect(wrapper.findAll('.family')).toHaveLength(3);
  });

  test('says so when the server reports nothing, and when it cannot be reached', async () => {
    const none = await boot(server('admin', { 'GET /api/v1/metrics': () => plain(200, '') }), '/metrics');
    expect(none.wrapper.text()).toContain('The server reported no metrics.');
    document.body.innerHTML = '';
    const failed = await boot(server('admin', { 'GET /api/v1/metrics': () => failure(500, 'internal_error') }), '/metrics');
    expect(failed.wrapper.get('[role=alert]').text()).toContain('The metrics could not be loaded.');
    expect(failed.wrapper.find('.family').exists()).toBe(false);
  });

  test('does not read the metrics as JSON, and sends no more than the one request', async () => {
    const s = server();
    await boot(s, '/metrics');
    const reads = s.requests.filter((r) => r.url.startsWith('/api/v1/metrics'));
    expect(reads).toHaveLength(1);
    expect(reads[0]?.method).toBe('GET');
  });
});

describe('the pages for the administration', () => {
  test('are in the navigation of an administrator', async () => {
    const { wrapper } = await boot(server(), '/');
    const labels = wrapper.findAll('nav a').map((a) => a.text());
    expect(labels).toContain('Audit log');
    expect(labels).toContain('Metrics');
  });

  test.each(['user', 'viewer'] as const)('are hidden from the role %s, and do not open', async (role) => {
    const { wrapper, router } = await boot(server(role), '/');
    const labels = wrapper.findAll('nav a').map((a) => a.text());
    expect(labels).not.toContain('Audit log');
    expect(labels).not.toContain('Metrics');
    for (const target of ['/audit', '/metrics']) {
      await router.push(target);
      await arrive(router, 'forbidden');
    }
  });

  test('speak German, and keep the values as they are', async () => {
    const { wrapper, i18n, router } = await boot(server(), '/audit');
    i18n.setLocale('de');
    await flushPromises();
    expect(wrapper.text()).toContain('Ge\u00E4nderte Felder');
    expect(wrapper.text()).toContain('honeytoken.update');
    await router.push('/metrics');
    await arrive(router, 'metrics');
    expect(wrapper.get('h1').text()).toBe('Metriken');
    expect(wrapper.text()).toContain('nyktus_event_jobs');
  });
});
