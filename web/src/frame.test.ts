// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises } from '@vue/test-utils';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { arrive, boot } from './testing/boot';
import { fakeServer, incidentId, json, sessionBody } from './testing/fakeServer';

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
    expect(groups).toHaveLength(3);
    expect(groups.map((g) => g.get('.group-label').text())).toEqual(['Detect', 'Inventory', 'Administration']);
    expect(groups[0]?.findAll('a').map((a) => a.text())).toEqual(['Overview', 'Incidents']);
    expect(groups[1]?.findAll('a').map((a) => a.text())).toEqual(['Honeytokens', 'Honeypots', 'Scenarios', 'Catalog']);
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

  test('has no language choice: it is on the account page', async () => {
    const { wrapper } = await boot(server('admin'), '/');
    expect(wrapper.find('header select').exists()).toBe(false);
  });

  describe('the page that is open', () => {
    test('is marked as the current page', async () => {
      const { wrapper } = await boot(server('admin'), '/incidents');
      const links = wrapper.findAll('nav a');
      expect(links.filter((a) => a.classes().includes('current')).map((a) => a.text())).toEqual(['Incidents']);
      expect(links.find((a) => a.text() === 'Incidents')!.attributes('aria-current')).toBe('page');
    });

    test('keeps its list marked on a page of the list, which is not the page itself', async () => {
      const { wrapper } = await boot(server('admin'), `/incidents/${incidentId}`);
      const incidents = wrapper.findAll('nav a').find((a) => a.text() === 'Incidents')!;
      expect(incidents.classes()).toContain('current');
      expect(incidents.attributes('aria-current')).toBeUndefined();
    });

    test('marks the administration when a page of it is open', async () => {
      const { wrapper } = await boot(server('admin'), '/users');
      expect(wrapper.get('.admin-button').classes()).toContain('current');
      expect(wrapper.findAll('nav a').filter((a) => a.classes().includes('current')).map((a) => a.text())).toEqual(['Accounts']);
    });

    test('marks the administration only when a page of it is open', async () => {
      const { wrapper } = await boot(server('admin'), '/honeytokens');
      expect(wrapper.get('.admin-button').classes()).not.toContain('current');
    });
  });

  describe('the administration', () => {
    test('is one entry that opens the list of its pages, and is closed at first', async () => {
      const { wrapper } = await boot(server('admin'), '/');
      const button = wrapper.get('.admin-button');
      const list = wrapper.get('.group-admin ul');
      expect(button.text()).toBe('Administration');
      expect(button.attributes('aria-expanded')).toBe('false');
      expect(button.attributes('aria-controls')).toBe(list.attributes('id'));
      expect(list.classes()).not.toContain('open');
      await button.trigger('click');
      expect(button.attributes('aria-expanded')).toBe('true');
      expect(list.classes()).toContain('open');
      await button.trigger('click');
      expect(list.classes()).not.toContain('open');
    });

    test('is closed by Escape, and the focus goes back to its button', async () => {
      const { wrapper } = await boot(server('admin'), '/');
      const button = wrapper.get('.admin-button');
      await button.trigger('click');
      (wrapper.findAll('.group-admin a')[0]!.element as HTMLElement).focus();
      await wrapper.get('header').trigger('keydown', { key: 'Escape' });
      expect(wrapper.get('.group-admin ul').classes()).not.toContain('open');
      expect(document.activeElement).toBe(button.element);
    });

    test('is closed by a click anywhere else', async () => {
      const { wrapper } = await boot(server('admin'), '/');
      await wrapper.get('.admin-button').trigger('click');
      expect(wrapper.get('.group-admin ul').classes()).toContain('open');
      document.body.click();
      await flushPromises();
      expect(wrapper.get('.group-admin ul').classes()).not.toContain('open');
    });

    test('stays open for a click inside it that is no link', async () => {
      const { wrapper } = await boot(server('admin'), '/');
      await wrapper.get('.admin-button').trigger('click');
      (wrapper.get('.group-admin ul').element as HTMLElement).click();
      await flushPromises();
      expect(wrapper.get('.group-admin ul').classes()).toContain('open');
    });

    test('is closed when the focus moves to something outside of it', async () => {
      const { wrapper } = await boot(server('admin'), '/');
      await wrapper.get('.admin-button').trigger('click');
      await wrapper.get('.group-admin').trigger('focusout', { relatedTarget: wrapper.get('main').element });
      expect(wrapper.get('.group-admin ul').classes()).not.toContain('open');
    });

    test('is closed by a page that the user opens from it', async () => {
      const { wrapper, router } = await boot(server('admin'), '/');
      await wrapper.get('.admin-button').trigger('click');
      await wrapper.findAll('.group-admin a').find((a) => a.text() === 'Audit log')!.trigger('click');
      await arrive(router, 'audit');
      expect(wrapper.get('.group-admin ul').classes()).not.toContain('open');
    });

    test('is not offered to a role that has none of its pages', async () => {
      const { wrapper } = await boot(server('viewer'), '/');
      expect(wrapper.find('.admin-button').exists()).toBe(false);
      expect(wrapper.find('.group-admin').exists()).toBe(false);
    });
  });

  describe('on a narrow screen', () => {
    test('is closed behind a button that says so, and opens and closes with it', async () => {
      const { wrapper } = await boot(server('admin'), '/');
      const button = wrapper.get('.menu-button');
      expect(button.attributes('aria-expanded')).toBe('false');
      expect(button.attributes('aria-controls')).toBe('main-nav');
      expect(wrapper.get('.tabs').classes()).not.toContain('open');
      await button.trigger('click');
      expect(button.attributes('aria-expanded')).toBe('true');
      expect(wrapper.get('.tabs').classes()).toContain('open');
      await button.trigger('click');
      expect(button.attributes('aria-expanded')).toBe('false');
    });

    test('is closed again by a page that the user opens', async () => {
      const { wrapper, router } = await boot(server('admin'), '/');
      await wrapper.get('.menu-button').trigger('click');
      await wrapper.findAll('nav a').find((a) => a.text() === 'Incidents')!.trigger('click');
      await arrive(router, 'incidents');
      expect(wrapper.get('.tabs').classes()).not.toContain('open');
      expect(wrapper.get('.menu-button').attributes('aria-expanded')).toBe('false');
    });

    test('is closed by a click on the link of the page that is open, which changes no path', async () => {
      const { wrapper } = await boot(server('admin'), '/');
      await wrapper.get('.menu-button').trigger('click');
      expect(wrapper.get('.tabs').classes()).toContain('open');
      await wrapper.findAll('nav a').find((a) => a.text() === 'Overview')!.trigger('click');
      await flushPromises();
      expect(wrapper.get('.tabs').classes()).not.toContain('open');
      expect(wrapper.get('.menu-button').attributes('aria-expanded')).toBe('false');
    });

    test('is closed by Escape, and the focus goes back to the button', async () => {
      const { wrapper } = await boot(server('admin'), '/');
      const button = wrapper.get('.menu-button');
      await button.trigger('click');
      (wrapper.findAll('nav a')[0]!.element as HTMLElement).focus();
      await wrapper.get('header').trigger('keydown', { key: 'Escape' });
      expect(wrapper.get('.tabs').classes()).not.toContain('open');
      expect(document.activeElement).toBe(button.element);
    });

    test('keeps the focus where it is when Escape is pressed with the menu closed', async () => {
      const { wrapper } = await boot(server('admin'), '/');
      const signOut = wrapper.get('.account button').element as HTMLElement;
      signOut.focus();
      await wrapper.get('header').trigger('keydown', { key: 'Escape' });
      expect(document.activeElement).toBe(signOut);
    });

    test('names the element that the button controls', async () => {
      const { wrapper } = await boot(server('admin'), '/');
      expect(document.getElementById(wrapper.get('.menu-button').attributes('aria-controls') ?? '')).not.toBeNull();
    });
  });
});
