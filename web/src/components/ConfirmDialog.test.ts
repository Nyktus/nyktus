// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { mount } from '@vue/test-utils';
import { describe, expect, test } from 'vitest';
import ConfirmDialog from './ConfirmDialog.vue';

function dialog(busy: boolean) {
  return mount(ConfirmDialog, { props: { open: false, title: 'Delete?', confirm: 'Delete', busy }, slots: { default: 'Body' } });
}

describe('ConfirmDialog', () => {
  test('asks to be closed by its button and by Escape, which the browser would otherwise close on its own', async () => {
    const wrapper = dialog(false);
    await wrapper.get('.button-ghost').trigger('click');
    const escape = new Event('cancel', { cancelable: true });
    wrapper.get('dialog').element.dispatchEvent(escape);
    expect(wrapper.emitted('cancel')).toHaveLength(2);
    expect(escape.defaultPrevented).toBe(true);
  });

  test('stays open while the request is on its way: neither its button nor Escape closes it, nor confirms again', async () => {
    const wrapper = dialog(true);
    expect(wrapper.get('.button-ghost').attributes('disabled')).toBeDefined();
    expect(wrapper.get('.danger').attributes('disabled')).toBeDefined();
    await wrapper.get('.button-ghost').trigger('click');
    await wrapper.get('.danger').trigger('click');
    const escape = new Event('cancel', { cancelable: true });
    wrapper.get('dialog').element.dispatchEvent(escape);
    expect(wrapper.emitted('cancel')).toBeUndefined();
    expect(wrapper.emitted('confirm')).toBeUndefined();
    expect(escape.defaultPrevented).toBe(true);
  });

  test('confirms by its button', async () => {
    const wrapper = dialog(false);
    await wrapper.get('.danger').trigger('click');
    expect(wrapper.emitted('confirm')).toHaveLength(1);
  });
});
