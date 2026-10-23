// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises } from '@vue/test-utils';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { arrive, boot } from './testing/boot';
import { fakeServer, json, sessionBody } from './testing/fakeServer';

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = '';
  history.replaceState(null, '', '/');
});

function server(role: 'admin' | 'user' | 'viewer') {
  return fakeServer({ 'GET /api/v1/session': () => json(200, sessionBody(role)), 'GET /api/v1/incidents': () => json(200, { incidents: [] }) });
}

describe('the navigation of the frame', () => {
  test('names the groups, with the pages of each, for an administrator', async () => {
    const { wrapper } = await boot(server('admin'), '/');
    const groups = wrapper.findAll('nav .group');
    expect(groups.map((g) => g.get('.group-label').text())).toEqual(['Detect', 'Inventory', 'Administration']);
    expect(groups[0]?.findAll('a').map((a) => a.text())).toEqual(['Overview', 'Incidents']);
    expect(groups[1]?.findAll('a').map((a) => a.text())).toEqual(['Honeytokens', 'Honeypots', 'Scenarios', 'Artifacts', 'Catalog']);
    expect(groups[2]?.findAll('a').map((a) => a.text())).toEqual(['Alert channels', 'Accounts', 'API keys', 'Audit log', 'Metrics']);
  });

  test('is a navigation with a name, and every group is a list that its heading names', async () => {
    const { wrapper } = await boot(server('admin'), '/');
    expect(wrapper.get('nav').attributes('aria-label')).toBe('Main navigation');
    for (const group of wrapper.findAll('nav .group')) {
      const named = group.get('ul').attributes('aria-labelledby') ?? '';
      expect(document.getElementById(named)?.textContent, 'the heading of the list').toBe(group.get('.group-label').text());
    }
  });

  test.each(['user', 'viewer'] as const)('has no group for the administration for the role %s', async (role) => {
    const { wrapper } = await boot(server(role), '/');
    expect(wrapper.findAll('nav .group-label').map((l) => l.text())).toEqual(['Detect', 'Inventory']);
  });

  test('speaks German', async () => {
    const { wrapper, i18n } = await boot(server('admin'), '/');
    i18n.setLocale('de');
    await flushPromises();
    expect(wrapper.findAll('nav .group-label').map((l) => l.text())).toEqual(['Erkennen', 'Inventar', 'Verwaltung']);
    expect(wrapper.get('.menu-button').text()).toBe('Men\u00FC');
  });

  describe('on a narrow screen', () => {
    test('is closed behind a button that says so, and opens and closes with it', async () => {
      const { wrapper } = await boot(server('admin'), '/');
      const button = wrapper.get('.menu-button');
      expect(button.attributes('aria-expanded')).toBe('false');
      expect(button.attributes('aria-controls')).toBe('main-nav');
      expect(wrapper.get('nav').classes()).not.toContain('open');
      await button.trigger('click');
      expect(button.attributes('aria-expanded')).toBe('true');
      expect(wrapper.get('nav').classes()).toContain('open');
      await button.trigger('click');
      expect(button.attributes('aria-expanded')).toBe('false');
    });

    test('is closed again by a page that the user opens', async () => {
      const { wrapper, router } = await boot(server('admin'), '/');
      await wrapper.get('.menu-button').trigger('click');
      await wrapper.findAll('nav a').find((a) => a.text() === 'Incidents')!.trigger('click');
      await arrive(router, 'incidents');
      expect(wrapper.get('nav').classes()).not.toContain('open');
      expect(wrapper.get('.menu-button').attributes('aria-expanded')).toBe('false');
    });

    test('is closed by a click on the link of the page that is open, which changes no path', async () => {
      const { wrapper } = await boot(server('admin'), '/');
      await wrapper.get('.menu-button').trigger('click');
      expect(wrapper.get('nav').classes()).toContain('open');
      await wrapper.findAll('nav a').find((a) => a.text() === 'Overview')!.trigger('click');
      await flushPromises();
      expect(wrapper.get('nav').classes()).not.toContain('open');
      expect(wrapper.get('.menu-button').attributes('aria-expanded')).toBe('false');
    });

    test('is closed by Escape, and the focus goes back to the button', async () => {
      const { wrapper } = await boot(server('admin'), '/');
      const button = wrapper.get('.menu-button');
      await button.trigger('click');
      (wrapper.findAll('nav a')[0]!.element as HTMLElement).focus();
      await wrapper.get('header').trigger('keydown', { key: 'Escape' });
      expect(wrapper.get('nav').classes()).not.toContain('open');
      expect(document.activeElement).toBe(button.element);
    });

    test('keeps the focus where it is when Escape is pressed with the menu closed', async () => {
      const { wrapper } = await boot(server('admin'), '/');
      const select = wrapper.get('select').element;
      select.focus();
      await wrapper.get('header').trigger('keydown', { key: 'Escape' });
      expect(document.activeElement).toBe(select);
    });

    test('names the element that the button controls', async () => {
      const { wrapper } = await boot(server('admin'), '/');
      expect(document.getElementById(wrapper.get('.menu-button').attributes('aria-controls') ?? '')).not.toBeNull();
    });
  });
});
