// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { flushPromises, mount } from '@vue/test-utils';
import { afterEach, expect, test, vi } from 'vitest';
import CopyButton from './CopyButton.vue';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

test('copies the value and says so for a moment', async () => {
  vi.useFakeTimers();
  const writeText = vi.fn().mockResolvedValue(undefined);
  vi.stubGlobal('navigator', { clipboard: { writeText } });
  const wrapper = mount(CopyButton, { props: { value: 'https://t.example.net/abc' } });
  expect(wrapper.text()).toBe('Copy');
  await wrapper.get('button').trigger('click');
  await flushPromises();
  expect(writeText).toHaveBeenCalledExactlyOnceWith('https://t.example.net/abc');
  expect(wrapper.text()).toBe('Copied');
  await vi.advanceTimersByTimeAsync(2100);
  expect(wrapper.text()).toBe('Copy');
});

test('does not claim to have copied when the browser refuses', async () => {
  vi.stubGlobal('navigator', { clipboard: { writeText: vi.fn().mockRejectedValue(new DOMException('no', 'NotAllowedError')) } });
  const wrapper = mount(CopyButton, { props: { value: 'x' } });
  await wrapper.get('button').trigger('click');
  await flushPromises();
  expect(wrapper.text()).toBe('Copy');
});

test('is not offered where the browser has no clipboard', () => {
  vi.stubGlobal('navigator', {});
  expect(mount(CopyButton, { props: { value: 'x' } }).find('button').exists()).toBe(false);
});
