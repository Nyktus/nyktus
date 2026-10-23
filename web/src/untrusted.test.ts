// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { mount } from '@vue/test-utils';
import { describe, expect, test } from 'vitest';
import UntrustedText from './components/UntrustedText.vue';
import { segments } from './untrusted';

describe('segments', () => {
  test('keeps plain text whole', () => {
    expect(segments('curl/8.4.0 (x86_64)')).toEqual([{ kind: 'text', text: 'curl/8.4.0 (x86_64)' }]);
  });

  test.each([
    ['\u3164', 'U+3164'],
    ['\u2800', 'U+2800'],
    ['\u034F', 'U+034F'],
    ['\u115F', 'U+115F'],
    ['\u1160', 'U+1160'],
    ['\uFE00', 'U+FE00'],
    ['\u{E01EF}', 'U+E01EF'],
    ['\uFE0F', 'U+FE0F'],
    ['\u{E0100}', 'U+E0100'],
    ['\u202E', 'U+202E'],
    ['\u200B', 'U+200B'],
    ['\u0007', 'U+0007'],
    ['\u0085', 'U+0085'],
    ['\uFFA0', 'U+FFA0'],
    ['\u00A0', 'U+00A0'],
    ['\u1680', 'U+1680'],
    ['\u2000', 'U+2000'],
    ['\u200A', 'U+200A'],
    ['\u202F', 'U+202F'],
    ['\u205F', 'U+205F'],
    ['\u3000', 'U+3000'],
    ['\u2028', 'U+2028'],
    ['\u2029', 'U+2029'],
    ['\u17B4', 'U+17B4'],
    ['\u17B5', 'U+17B5'],
    ['\u180B', 'U+180B'],
    ['\u180D', 'U+180D'],
  ])('marks %j, which shows nothing or reorders text', (character, label) => {
    expect(segments(`a${character}b`)).toEqual([
      { kind: 'text', text: 'a' },
      { kind: 'hidden', label: `\u2039${label}\u203A` },
      { kind: 'text', text: 'b' },
    ]);
  });

  test('leaves the ordinary space and the letters of other scripts alone', () => {
    expect(segments('two words')).toEqual([{ kind: 'text', text: 'two words' }]);
    expect(segments('\u00E9\u4E2D\u0628')).toEqual([{ kind: 'text', text: '\u00E9\u4E2D\u0628' }]);
  });

  test('marks every character of a run and keeps right-to-left letters as text', () => {
    expect(segments('\u3164\u3164')).toHaveLength(2);
    expect(segments('\u05E9\u05DC\u05D5\u05DD')).toEqual([{ kind: 'text', text: '\u05E9\u05DC\u05D5\u05DD' }]);
  });
});

describe('UntrustedText', () => {
  const draw = (value: string | null) => mount(UntrustedText, { props: { value } });

  test('draws markup as text', () => {
    const wrapper = draw('<img src=x onerror=alert(1)>');
    expect(wrapper.find('img').exists()).toBe(false);
    expect(wrapper.text()).toBe('<img src=x onerror=alert(1)>');
  });

  test('isolates the direction of the text', () => {
    const bdi = draw('\u05E9\u05DC\u05D5\u05DD admin').get('bdi');
    expect(bdi.attributes('dir')).toBe('ltr');
    expect(bdi.classes()).toContain('untrusted');
  });

  test('shows a marker for a character that shows nothing', () => {
    const wrapper = draw('root\u3164');
    expect(wrapper.get('.marker').text()).toBe('\u2039U+3164\u203A');
    expect(wrapper.text()).toBe('root\u2039U+3164\u203A');
  });

  test('says so for an empty value and for none', () => {
    expect(draw('').text()).toBe('(empty)');
    expect(draw('').find('bdi').exists()).toBe(false);
    expect(draw(null).text()).toBe('None');
  });

  test('puts the value in no attribute', () => {
    const html = draw('secret-looking-value').html();
    expect(html.replace('>secret-looking-value<', '')).not.toContain('secret-looking-value');
  });

  test('does not shorten a long value', () => {
    const long = 'a'.repeat(5000);
    expect(draw(long).text()).toHaveLength(5000);
  });
});
