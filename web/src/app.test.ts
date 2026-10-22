// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { mount } from '@vue/test-utils';
import { expect, test } from 'vitest';
import App from './App.vue';

test('the shell shows the name of the product', () => {
  expect(mount(App).get('h1').text()).toBe('Nyktus');
});
