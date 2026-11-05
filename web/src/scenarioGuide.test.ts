// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises } from '@vue/test-utils';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { arrive, boot, submit, type } from './testing/boot';
import { catalogDeception, catalogSummary, fakeServer, honeypot, honeytoken, joined, json, scenario, scenarioId, sessionBody } from './testing/fakeServer';

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = '';
  history.replaceState(null, '', '/');
});

type Role = 'admin' | 'user' | 'viewer';

const detail = `/api/v1/scenarios/${scenarioId}`;
const deceptionPath = '/api/v1/catalog/deceptions/database-credentials';

// A deception that asks for two honeytokens and a honeypot, as the guide of a story about a database would.
const asking = catalogDeception({
  id: 'database-credentials',
  title: 'Database credentials',
  honeytokens: [
    { label: 'Database host', type: 'dns', techniques: ['T1552.001', 'T1078'], severity: 'high' },
    { label: 'Admin portal', type: 'web_url', techniques: [], severity: 'medium' },
  ],
  honeypots: [{ label: 'Database', service: 'postgres' }],
  files: [{ name: 'config.ini', format: 'config', size: 118 }],
});

function server(role: Role = 'admin', extra: Record<string, () => Response> = {}) {
  return fakeServer({
    'GET /api/v1/session': () => json(200, sessionBody(role)),
    [`GET ${detail}`]: () => json(200, scenario({ deceptions: [joined('database-credentials')] })),
    'GET /api/v1/honeytokens': () => json(200, { honeytokens: [] }),
    'GET /api/v1/honeypots': () => json(200, { honeypots: [] }),
    'GET /api/v1/scenarios': () => json(200, { scenarios: [scenario()] }),
    'GET /api/v1/catalog/deceptions': () => json(200, { deceptions: [catalogSummary({ id: 'database-credentials', title: 'Database credentials' })] }),
    [`GET ${deceptionPath}`]: () => json(200, asking),
    ...extra,
  });
}

/** The panel that a heading names, such as the table of the honeytokens of the scenario. */
function panel(wrapper: Awaited<ReturnType<typeof boot>>['wrapper'], title: string) {
  const found = wrapper.findAll('.section').find((p) => p.find('h2').exists() && p.get('h2').text() === title);
  if (found === undefined) {
    throw new Error(`no panel named ${title}`);
  }
  return found;
}

/** The query of a link, as a plain object, so that the order of the parameters does not matter. */
function queryOf(href: string | undefined): Record<string, string> {
  return Object.fromEntries(new URL(href ?? '', 'https://console.test').searchParams);
}

describe('what a deception asks for, in a scenario', () => {
  const path = `/scenarios/${scenarioId}`;

  test('is a row for each honeytoken and honeypot, with a link that creates it in the scenario', async () => {
    const { wrapper } = await boot(server(), path);
    const links = wrapper.findAll('.story a.button');
    expect(links.map((a) => a.attributes('aria-label'))).toEqual(['Create "Database host"', 'Create "Admin portal"', 'Create "Database"']);
    expect(links.map((a) => a.text())).toEqual(['Create', 'Create', 'Create']);
    expect(links[0]?.attributes('href')?.startsWith('/honeytokens/new?')).toBe(true);
    expect(queryOf(links[0]?.attributes('href'))).toEqual({ scenario: scenarioId, type: 'dns', name: 'Database host', severity: 'high', techniques: 'T1552.001,T1078' });
    expect(queryOf(links[1]?.attributes('href'))).toEqual({ scenario: scenarioId, type: 'web_url', name: 'Admin portal', severity: 'medium' });
    expect(links[2]?.attributes('href')?.startsWith('/honeypots/new?')).toBe(true);
    expect(queryOf(links[2]?.attributes('href'))).toEqual({ scenario: scenarioId, service: 'postgres', name: 'Database' });
  });

  test('names the list of the slots, and says where the value of a honeytoken is placed in the files', async () => {
    const { wrapper } = await boot(server(), path);
    expect(wrapper.get('.story h4').text()).toBe('What this deception asks for');
    expect(wrapper.get('.story').text()).toContain('The value stands in the table "Honeytokens of this scenario" below.');
    expect(wrapper.get('.story').text()).toContain('adapt them to your environment');
    expect(wrapper.get('.story').text()).toContain('config.ini');
  });

  test('says nothing about the table of honeytokens where the deception asks for none', async () => {
    const s = server('admin', { [`GET ${deceptionPath}`]: () => json(200, { ...asking, honeytokens: [] }) });
    const { wrapper } = await boot(s, path);
    expect(wrapper.get('.story').text()).not.toContain('The value stands in the table');
  });

  test('is offered to create only to whoever may write that kind of resource, and in no catalog page', async () => {
    for (const [role, offered] of [['admin', true], ['user', true], ['viewer', false]] as const) {
      const { wrapper } = await boot(server(role), path);
      expect(wrapper.findAll('.story a.button').length > 0, role).toBe(offered);
      document.body.innerHTML = '';
    }
    const { wrapper } = await boot(server(), '/catalog/database-credentials');
    expect(wrapper.findAll('a.button').filter((a) => (a.attributes('href') ?? '').includes('/new?'))).toHaveLength(0);
  });

  test('speaks German with the German texts of the console', async () => {
    const { wrapper, i18n } = await boot(server(), path);
    i18n.setLocale('de');
    await flushPromises();
    expect(wrapper.get('.story h4').text()).toBe('Das verlangt die Deception');
    expect(wrapper.findAll('.story a.button')[0]?.text()).toBe('Anlegen');
    expect(wrapper.findAll('.story a.button')[0]?.attributes('aria-label')).toBe('„Database host“ anlegen');
    expect(wrapper.get('.story').text()).toContain('Den Wert finden Sie unten in der Tabelle „Honeytokens dieses Szenarios“.');
  });
});

describe('the honeytokens and honeypots of a scenario', () => {
  const path = `/scenarios/${scenarioId}`;
  const url = honeytoken({ scenario_id: scenarioId });
  const dns = honeytoken({
    id: 'c0ffee00-2222-4222-8333-944444444444',
    type: 'dns',
    name: 'Database host',
    trigger_url: null,
    trigger_names: ['abcdefghijklmnopqrstuvwxyz.dns.example.net', 'abcdefghijklmnopqrstuvwxyz.dns.example.org'],
    scenario_id: scenarioId,
  });

  test('show the value to place of each honeytoken, every name of a DNS honeytoken, each with a button that copies it', async () => {
    const s = server('admin', { 'GET /api/v1/honeytokens': () => json(200, { honeytokens: [url, dns] }) });
    const { wrapper } = await boot(s, path);
    const table = panel(wrapper, 'Honeytokens of this scenario');
    const rows = table.findAll('tbody tr');
    expect(rows.map((r) => r.findAll('.value .mono').map((v) => v.text()))).toEqual([
      ['https://t.example.net/abcdefghijklmnopqrstuvwxyz'],
      ['abcdefghijklmnopqrstuvwxyz.dns.example.net', 'abcdefghijklmnopqrstuvwxyz.dns.example.org'],
    ]);
    expect(rows.flatMap((r) => r.findAll('.value button').map((b) => b.attributes('aria-label')))).toEqual([
      'Copy: https://t.example.net/abcdefghijklmnopqrstuvwxyz',
      'Copy: abcdefghijklmnopqrstuvwxyz.dns.example.net',
      'Copy: abcdefghijklmnopqrstuvwxyz.dns.example.org',
    ]);
    expect(table.findAll('th').map((h) => h.text())).toEqual(['Name', 'Type', 'Status', 'Severity', 'Value to place', '']);
  });

  test('show a honeypot with its service and status, and no value to place', async () => {
    const s = server('admin', { 'GET /api/v1/honeypots': () => json(200, { honeypots: [honeypot({ scenario_id: scenarioId, service: 'postgres' })] }) });
    const { wrapper } = await boot(s, path);
    const table = panel(wrapper, 'Honeypots of this scenario');
    expect(table.findAll('th').map((h) => h.text())).toEqual(['Name', 'Type', 'Status', 'Severity', '']);
    expect(table.get('tbody tr').text()).toContain('Jump host');
    expect(table.get('tbody tr').text()).toContain('PostgreSQL');
  });

  test('have one table for the whole scenario, however many deceptions it holds', async () => {
    const s = server('admin', {
      [`GET ${detail}`]: () => json(200, scenario({ deceptions: [joined('database-credentials'), joined('browser-bookmarks')] })),
      'GET /api/v1/honeytokens': () => json(200, { honeytokens: [url] }),
    });
    const { wrapper } = await boot(s, path);
    expect(wrapper.findAll('h2').filter((h) => h.text() === 'Honeytokens of this scenario')).toHaveLength(1);
    expect(wrapper.findAll('.story table tbody tr').filter((r) => r.text().includes('Backup share link'))).toHaveLength(0);
  });
});

describe('the form that a slot opens', () => {
  const link = (query: string) => `/honeytokens/new?${query}`;

  test('is filled with the type, the name, the severity and the techniques of the slot, and joins the scenario', async () => {
    const query = new URLSearchParams({ scenario: scenarioId, type: 'dns', name: 'Database host', severity: 'high', techniques: 'T1552.001,T1078' });
    const { wrapper } = await boot(server(), link(query.toString()));
    expect(wrapper.get<HTMLSelectElement>('#type').element.value).toBe('dns');
    expect(wrapper.get<HTMLInputElement>('#name').element.value).toBe('Database host');
    expect(wrapper.get<HTMLSelectElement>('#severity').element.value).toBe('high');
    expect(wrapper.get<HTMLInputElement>('#techniques').element.value).toBe('T1552.001, T1078');
    expect(wrapper.get<HTMLSelectElement>('#scenario').element.value).toBe(scenarioId);
  });

  test('sends what is in the form, which the person may have changed', async () => {
    const s = server('admin', { 'POST /api/v1/honeytokens': () => json(201, honeytoken({ scenario_id: scenarioId })) });
    const { wrapper } = await boot(s, link(`scenario=${scenarioId}&type=dns&name=Database%20host&severity=high&techniques=T1552.001`));
    await type(wrapper, '#name', 'Billing database host');
    await submit(wrapper);
    expect(s.requests.find((r) => r.method === 'POST')?.body).toEqual({
      type: 'dns',
      name: 'Billing database host',
      notes: '',
      enabled: true,
      techniques: ['T1552.001'],
      severity: 'high',
      scenario_id: scenarioId,
    });
  });

  // The address is written by whoever sends a link, so the form takes over only what it offers itself.
  test('takes over nothing that the form does not offer, and shows no value from the address as markup', async () => {
    const query = new URLSearchParams({
      type: 'script',
      severity: 'urgent',
      name: '<img src=x onerror=alert(1)>',
      techniques: 'javascript:alert(1),<b>',
    });
    const { wrapper } = await boot(server(), link(query.toString()));
    expect(wrapper.get<HTMLSelectElement>('#type').element.value).toBe('web_url');
    expect(wrapper.get<HTMLSelectElement>('#severity').element.value).toBe('');
    expect(wrapper.get<HTMLInputElement>('#techniques').element.value).toBe('');
    // A name is text for a field of the form: it stays what it was written as, and nothing turns it into an element.
    expect(wrapper.get<HTMLInputElement>('#name').element.value).toBe('<img src=x onerror=alert(1)>');
    expect(wrapper.find('form img').exists()).toBe(false);
  });

  test('takes a service of the honeypot form only from the services it offers', async () => {
    const { wrapper } = await boot(server(), `/honeypots/new?scenario=${scenarioId}&service=postgres&name=Database`);
    expect(wrapper.get<HTMLSelectElement>('#service').element.value).toBe('postgres');
    expect(wrapper.get<HTMLInputElement>('#name').element.value).toBe('Database');
    document.body.innerHTML = '';
    const other = await boot(server(), '/honeypots/new?service=mysql');
    expect(other.wrapper.get<HTMLSelectElement>('#service').element.value).toBe('ssh');
  });

  test('leads back to the scenario once the honeytoken is created in it', async () => {
    const s = server('admin', { 'POST /api/v1/honeytokens': () => json(201, honeytoken({ scenario_id: scenarioId })) });
    const { wrapper, router } = await boot(s, link(`scenario=${scenarioId}&name=Portal`));
    await submit(wrapper);
    await arrive(router, 'scenario');
    expect(router.currentRoute.value.params.id).toBe(scenarioId);
    // The page that it leads to says that the honeytoken was created, as the page of the honeytoken would.
    expect(wrapper.get('[role=status]').text()).toContain('The honeytoken has been created.');
  });

  // The note belongs to the arrival: a reload or a link that is passed on must not say it again.
  test('says that the honeytoken was created once, and takes the note from the address', async () => {
    const s = server('admin', {
      'POST /api/v1/honeytokens': () => json(201, honeytoken({ scenario_id: scenarioId })),
      [`PATCH ${detail}`]: () => json(200, scenario({ notes: 'Moved' })),
    });
    const { wrapper, router } = await boot(s, link(`scenario=${scenarioId}&name=Portal`));
    await submit(wrapper);
    await arrive(router, 'scenario');
    await vi.waitFor(() => expect(router.currentRoute.value.query).toEqual({}));
    expect(wrapper.text()).toContain('The honeytoken has been created.');
    await type(wrapper, '#notes', 'Moved');
    await submit(wrapper);
    expect(wrapper.text()).not.toContain('The honeytoken has been created.');
  });

  test('leads to the honeytoken when it did not join the scenario of the link', async () => {
    const s = server('admin', {
      'POST /api/v1/honeytokens': () => json(201, honeytoken({ scenario_id: null })),
      'GET /api/v1/honeytokens/c0ffee00-1111-4222-8333-944444444444': () => json(200, honeytoken()),
    });
    const { wrapper, router } = await boot(s, link(`scenario=${scenarioId}&name=Portal`));
    await wrapper.get('#scenario').setValue('');
    await submit(wrapper);
    await arrive(router, 'honeytoken');
  });

  test('leads to the honeytoken when the page was not opened from a scenario', async () => {
    const s = server('admin', {
      'POST /api/v1/honeytokens': () => json(201, honeytoken({ scenario_id: scenarioId })),
      'GET /api/v1/honeytokens/c0ffee00-1111-4222-8333-944444444444': () => json(200, honeytoken({ scenario_id: scenarioId })),
    });
    const { wrapper, router } = await boot(s, '/honeytokens/new');
    await type(wrapper, '#name', 'Portal');
    await wrapper.get('#scenario').setValue(scenarioId);
    await submit(wrapper);
    await arrive(router, 'honeytoken');
  });
});

describe('adding a deception to a scenario', () => {
  test('names the labels of the slots as the names of what is created, and warns about a second round', async () => {
    const s = server('admin', { [`GET ${detail}`]: () => json(200, scenario()) });
    const { wrapper } = await boot(s, `/scenarios/${scenarioId}/deceptions/new`);
    await wrapper.get('#deception').setValue('database-credentials');
    await flushPromises();
    const text = wrapper.get('.field:has(#create-resources)').text();
    expect(text).toContain('They join the scenario under these names: Database host, Admin portal, Database.');
    expect(text).toContain('If you removed this deception before, the box creates its honeytokens and honeypots a second time.');
  });
});
