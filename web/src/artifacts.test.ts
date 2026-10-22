// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises } from '@vue/test-utils';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { arrive, boot, submit, type } from './testing/boot';
import { artifact, artifactId, failure, fakeServer, json, noContent, scenario, scenarioId, sessionBody } from './testing/fakeServer';

type Role = 'admin' | 'user' | 'viewer';

const one = `/api/v1/artifacts/${artifactId}`;
const path = `/artifacts/${artifactId}`;

function file(content: string, type = 'text/html') {
  return () => new Response(content, { status: 200, headers: { 'Content-Type': type, 'Content-Disposition': 'attachment; filename="bookmarks.html"', 'Cache-Control': 'no-store' } });
}

function server(role: Role = 'admin', extra: Record<string, () => Response> = {}) {
  return fakeServer({
    'GET /api/v1/session': () => json(200, sessionBody(role)),
    'GET /api/v1/artifacts': () => json(200, { artifacts: [artifact()] }),
    [`GET ${one}`]: () => json(200, artifact()),
    [`GET ${one}/content`]: file('<html><script>alert(1)</script></html>'),
    ...extra,
  });
}

// The console saves a file with a link that it makes, and never opens it.
const saved: { download: string; href: string }[] = [];
let revoked = 0;

beforeEach(() => {
  saved.length = 0;
  revoked = 0;
  vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: vi.fn(() => 'blob:console/1'), revokeObjectURL: vi.fn(() => revoked++) }));
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
    saved.push({ download: this.download, href: this.href });
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  document.body.innerHTML = '';
  history.replaceState(null, '', '/');
});

describe('the list of artifacts', () => {
  test('shows the files with their format and size', async () => {
    const big = artifact({ id: 'a11fac70-2222-4222-8333-944444444444', file_name: 'config', format: 'config', media_type: 'text/plain', size: 3_000_000 });
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/artifacts': () => json(200, { artifacts: [artifact(), big] }) }), '/artifacts');
    const rows = wrapper.findAll('tbody tr');
    expect(rows[0]?.text()).toContain('bookmarks.html');
    expect(rows[0]?.text()).toContain('HTML');
    expect(rows[0]?.text()).toContain('2 KiB');
    expect(rows[1]?.text()).toContain('Configuration');
    expect(rows[1]?.text()).toContain('2.9 MiB');
    expect(rows[0]?.get('a').attributes('href')).toBe(path);
  });

  test('says when there are none', async () => {
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/artifacts': () => json(200, { artifacts: [] }) }), '/artifacts');
    expect(wrapper.text()).toContain('There are no artifacts yet.');
  });

  test('is in the navigation of every role', async () => {
    const { wrapper } = await boot(server('viewer'), '/artifacts');
    expect(wrapper.get('nav').text()).toContain('Artifacts');
  });

  test('shows a file name that is markup as text', async () => {
    const hostile = artifact({ file_name: '<img src=x onerror=alert(1)>.html' });
    const { wrapper } = await boot(server('admin', { 'GET /api/v1/artifacts': () => json(200, { artifacts: [hostile] }) }), '/artifacts');
    expect(wrapper.find('img[src=x]').exists()).toBe(false);
  });
});

describe('an artifact', () => {
  test('shows what it is and where it was placed', async () => {
    const { wrapper } = await boot(server(), path);
    expect(wrapper.get('h1').text()).toBe('bookmarks.html');
    expect(wrapper.text()).toContain('text/html');
    expect(wrapper.text()).toContain('2 KiB');
    expect(wrapper.get('.notes').text()).toBe('On the share \\\\fs01\\it.');
    expect(wrapper.get('dl a').attributes('href')).toBe(`/scenarios/${scenarioId}`);
  });

  test('says when its scenario was deleted', async () => {
    const { wrapper } = await boot(server('admin', { [`GET ${one}`]: () => json(200, artifact({ scenario_id: null })) }), path);
    expect(wrapper.text()).toContain('None; the scenario was deleted');
  });

  test('says when it does not exist', async () => {
    const { wrapper } = await boot(server('admin', { [`GET ${one}`]: () => failure(404, 'not_found') }), path);
    expect(wrapper.get('[role=status]').text()).toBe('This does not exist.');
  });

  describe('downloaded', () => {
    test('is saved under its name, and not opened', async () => {
      const s = server();
      const { wrapper } = await boot(s, path);
      await wrapper.findAll('button').find((b) => b.text() === 'Download')!.trigger('click');
      await flushPromises();
      expect(s.requests.at(-1)?.url).toBe(`${one}/content`);
      expect(saved).toEqual([{ download: 'bookmarks.html', href: 'blob:console/1' }]);
      expect(URL.createObjectURL).toHaveBeenCalledOnce();
      expect(globalThis.location.href).not.toContain('blob:');
      // The link that saved it is gone again.
      expect(document.body.querySelectorAll('a[download]')).toHaveLength(0);
    });

    test('hands over the bytes that the server sent', async () => {
      const { wrapper } = await boot(server(), path);
      await wrapper.findAll('button').find((b) => b.text() === 'Download')!.trigger('click');
      await flushPromises();
      const blob = vi.mocked(URL.createObjectURL).mock.calls[0]?.[0] as Blob;
      expect(await blob.text()).toBe('<html><script>alert(1)</script></html>');
    });

    // The address of a file that was made for the download is not kept for long.
    test('lets go of the address of the file after a while', async () => {
      const { wrapper } = await boot(server(), path);
      vi.useFakeTimers({ toFake: ['setTimeout'] });
      try {
        await wrapper.findAll('button').find((b) => b.text() === 'Download')!.trigger('click');
        await flushPromises();
        expect(revoked).toBe(0);
        vi.advanceTimersByTime(9_000);
        expect(revoked).toBe(0);
        vi.advanceTimersByTime(1_000);
        expect(revoked).toBe(1);
      } finally {
        vi.useRealTimers();
      }
    });

    test('says when the file could not be downloaded', async () => {
      const { wrapper } = await boot(server('admin', { [`GET ${one}/content`]: () => failure(503, 'unavailable') }), path);
      await wrapper.findAll('button').find((b) => b.text() === 'Download')!.trigger('click');
      await flushPromises();
      expect(wrapper.get('[role=alert]').text()).toContain('The file could not be downloaded.');
      expect(saved).toHaveLength(0);
    });

    test('can be downloaded by a viewer', async () => {
      const { wrapper } = await boot(server('viewer'), path);
      expect(wrapper.findAll('button').map((b) => b.text())).toContain('Download');
    });
  });

  // An artifact can be HTML. In the origin of the console it would run with the rights of the user,
  // so the console shows its text and nothing else.
  describe('shown', () => {
    test('as text, however hostile', async () => {
      const content = '<html><body onload=alert(1)><script>alert(2)</script><img src=x onerror=alert(3)><a href="javascript:alert(4)">x</a></body></html>';
      const { wrapper } = await boot(server('admin', { [`GET ${one}/content`]: file(content) }), path);
      await wrapper.findAll('button').find((b) => b.text() === 'Show the content')!.trigger('click');
      await flushPromises();
      expect(wrapper.get('pre.content').text()).toBe(content);
      expect(wrapper.find('pre.content *').exists()).toBe(false);
      expect(wrapper.find('script').exists()).toBe(false);
      expect(wrapper.find('img[src=x]').exists()).toBe(false);
      expect(wrapper.find('a[href^=javascript]').exists()).toBe(false);
      expect(wrapper.find('iframe, object, embed').exists()).toBe(false);
    });

    test('can be hidden again', async () => {
      const { wrapper } = await boot(server(), path);
      const toggle = () => wrapper.findAll('button').find((b) => b.text() === 'Show the content' || b.text() === 'Hide the content')!;
      await toggle().trigger('click');
      await flushPromises();
      expect(wrapper.find('pre.content').exists()).toBe(true);
      await toggle().trigger('click');
      expect(wrapper.find('pre.content').exists()).toBe(false);
    });

    test('only in part when it is long', async () => {
      const long = 'x'.repeat(70 * 1024);
      const { wrapper } = await boot(server('admin', { [`GET ${one}/content`]: file(long) }), path);
      await wrapper.findAll('button').find((b) => b.text() === 'Show the content')!.trigger('click');
      await flushPromises();
      expect(wrapper.get('pre.content').text()).toHaveLength(64 * 1024);
      expect(wrapper.text()).toContain('Only the first 64 KiB are shown.');
    });

    test('without half a character at the end of the part that is shown', async () => {
      const content = `${'a'.repeat(64 * 1024 - 1)}\u00e4${'b'.repeat(100)}`;
      const { wrapper } = await boot(server('admin', { [`GET ${one}/content`]: file(content) }), path);
      await wrapper.findAll('button').find((b) => b.text() === 'Show the content')!.trigger('click');
      await flushPromises();
      const shown = wrapper.get('pre.content').text();
      expect(shown).toHaveLength(64 * 1024 - 1);
      expect(shown).not.toContain('\uFFFD');
    });

    test('with one request, however often the button is pressed', async () => {
      let answer: (response: Response) => void = () => undefined;
      const s = server('admin', { [`GET ${one}/content`]: () => new Promise<Response>((resolve) => (answer = resolve)) as never });
      const { wrapper } = await boot(s, path);
      const button = wrapper.findAll('button').find((b) => b.text() === 'Show the content')!;
      await button.trigger('click');
      await button.trigger('click');
      expect(button.attributes('disabled')).toBeDefined();
      answer(file('text')());
      await flushPromises();
      expect(s.requests.filter((r) => r.url.endsWith('/content'))).toHaveLength(1);
      expect(wrapper.get('pre.content').text()).toBe('text');
    });

    test('not at all when it is not text', async () => {
      const binary = artifact({ file_name: 'link.lnk', format: 'config', media_type: 'application/octet-stream' });
      const { wrapper } = await boot(server('admin', { [`GET ${one}`]: () => json(200, binary) }), path);
      expect(wrapper.text()).toContain('This file is not text; download it to open it.');
      expect(wrapper.findAll('button').map((b) => b.text())).not.toContain('Show the content');
    });
  });

  describe('with notes on where it is placed', () => {
    test('sends only the notes', async () => {
      const s = server('admin', { [`PATCH ${one}`]: () => json(200, artifact({ placement_notes: 'Moved', updated_at: '2026-10-22T10:00:00Z' })) });
      const { wrapper } = await boot(s, path);
      await type(wrapper, '#placement', 'Moved');
      await submit(wrapper);
      expect(s.requests.find((r) => r.method === 'PATCH')?.body).toEqual({ placement_notes: 'Moved' });
      expect(wrapper.get('.notes').text()).toBe('Moved');
      expect(wrapper.text()).toContain('Saved.');
    });

    test('can remove them with an empty text', async () => {
      const s = server('admin', { [`PATCH ${one}`]: () => json(200, artifact({ placement_notes: '' })) });
      const { wrapper } = await boot(s, path);
      await type(wrapper, '#placement', '');
      await submit(wrapper);
      expect(s.requests.find((r) => r.method === 'PATCH')?.body).toEqual({ placement_notes: '' });
    });

    test('send nothing when they did not change', async () => {
      const s = server();
      const { wrapper } = await boot(s, path);
      await submit(wrapper);
      expect(s.requests.filter((r) => r.method === 'PATCH')).toHaveLength(0);
    });

    test('are not for a viewer to change', async () => {
      const { wrapper } = await boot(server('viewer'), path);
      expect(wrapper.find('form').exists()).toBe(false);
      expect(wrapper.find('dialog').exists()).toBe(false);
      expect(wrapper.findAll('button').map((b) => b.text())).not.toContain('Delete');
    });
  });

  describe('deleted', () => {
    async function ask(extra: Record<string, () => Response> = {}) {
      const s = server('admin', { [`DELETE ${one}`]: noContent, ...extra });
      const app = await boot(s, path);
      await app.wrapper.findAll('button').find((b) => b.text() === 'Delete')!.trigger('click');
      await flushPromises();
      return { ...app, s };
    }

    test('only after the user confirms', async () => {
      const { wrapper, router, s } = await ask();
      expect(s.requests.filter((r) => r.method === 'DELETE')).toHaveLength(0);
      await wrapper.get('dialog[open] .danger').trigger('click');
      await flushPromises();
      expect(s.requests.filter((r) => r.method === 'DELETE')).toHaveLength(1);
      await arrive(router, 'artifacts');
    });

    test('not when the user cancels', async () => {
      const { wrapper, s } = await ask();
      await wrapper.get('dialog[open] .button-ghost').trigger('click');
      await flushPromises();
      expect(s.requests.filter((r) => r.method === 'DELETE')).toHaveLength(0);
    });
  });
});

describe('the artifacts of a scenario', () => {
  test('are listed on its page, asking for those of the scenario', async () => {
    const s = server('admin', {
      [`GET /api/v1/scenarios/${scenarioId}`]: () => json(200, scenario()),
      'GET /api/v1/honeytokens': () => json(200, { honeytokens: [] }),
      'GET /api/v1/honeypots': () => json(200, { honeypots: [] }),
    });
    const { wrapper } = await boot(s, `/scenarios/${scenarioId}`);
    expect(s.requests.map((r) => r.url)).toContain(`/api/v1/artifacts?limit=50&scenario_id=${scenarioId}`);
    expect(wrapper.text()).toContain('bookmarks.html');
  });

  test('say that they are loading, and load the next page once however often the button is pressed', async () => {
    let answer: (response: Response) => void = () => undefined;
    let first = true;
    const s = server('admin', {
      [`GET /api/v1/scenarios/${scenarioId}`]: () => json(200, scenario()),
      'GET /api/v1/honeytokens': () => json(200, { honeytokens: [] }),
      'GET /api/v1/honeypots': () => json(200, { honeypots: [] }),
      'GET /api/v1/artifacts': () => {
        if (first) {
          first = false;
          return json(200, { artifacts: [artifact()], next_cursor: 'c2' });
        }
        return new Promise<Response>((resolve) => (answer = resolve)) as never;
      },
    });
    const { wrapper } = await boot(s, `/scenarios/${scenarioId}`);
    const more = () => wrapper.findAll('button').find((b) => b.text() === 'Load more')!;
    await more().trigger('click');
    await more().trigger('click');
    expect(more().attributes('disabled')).toBeDefined();
    answer(json(200, { artifacts: [] }));
    await flushPromises();
    expect(s.requests.filter((r) => r.url.startsWith('/api/v1/artifacts'))).toHaveLength(2);
  });

  test('say that they are loading while the first page is on its way', async () => {
    const s = server('admin', {
      [`GET /api/v1/scenarios/${scenarioId}`]: () => json(200, scenario()),
      'GET /api/v1/honeytokens': () => json(200, { honeytokens: [] }),
      'GET /api/v1/honeypots': () => json(200, { honeypots: [] }),
      'GET /api/v1/artifacts': () => new Promise<Response>(() => undefined) as never,
    });
    const { wrapper } = await boot(s, `/scenarios/${scenarioId}`);
    const panel = wrapper.findAll('.section').find((p) => p.find('h2').exists() && p.get('h2').text() === 'Artifacts');
    expect(panel?.get('[role=status]').text()).toBe('Loading \u2026');
  });
});
