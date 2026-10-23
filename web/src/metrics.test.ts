// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, test } from 'vitest';
import { parseMetrics } from './metrics';

describe('parseMetrics', () => {
  test('reads a family with its help, type and sample', () => {
    const text = '# HELP nyktus_event_jobs Jobs of events that wait to be processed.\n# TYPE nyktus_event_jobs gauge\nnyktus_event_jobs 3\n';
    expect(parseMetrics(text)).toEqual({
      families: [{ name: 'nyktus_event_jobs', help: 'Jobs of events that wait to be processed.', type: 'gauge', samples: [{ labels: [], value: '3' }] }],
      other: [],
    });
  });

  test('reads labels, in the order they were written', () => {
    const text = '# TYPE nyktus_build_info gauge\nnyktus_build_info{version="0.1.0",go_version="go1.26"} 1\n';
    expect(parseMetrics(text).families[0]?.samples).toEqual([
      {
        labels: [
          ['version', '0.1.0'],
          ['go_version', 'go1.26'],
        ],
        value: '1',
      },
    ]);
  });

  test('keeps the samples of one family together, in the order of the family', () => {
    const text = 'a{status="x"} 1\nb 2\na{status="y"} 3\n';
    const { families } = parseMetrics(text);
    expect(families.map((f) => f.name)).toEqual(['a', 'b']);
    expect(families[0]?.samples.map((s) => s.value)).toEqual(['1', '3']);
  });

  test('reads escaped quotes, backslashes and line breaks in a label, and a comma in it', () => {
    const text = 'a{k="x\\"y\\\\z\\nw,v"} 1\n';
    expect(parseMetrics(text).families[0]?.samples[0]?.labels).toEqual([['k', 'x"y\\z\nw,v']]);
  });

  test('reads a help text with escapes, and one without text', () => {
    expect(parseMetrics('# HELP a one\\ntwo \\\\ three\n').families[0]?.help).toBe('one\ntwo \\ three');
    expect(parseMetrics('# HELP a\n').families[0]?.help).toBe('');
  });

  test.each(['1', '-1', '+1', '1.5', '.5', '1e9', '1.5E-3', 'Inf', '-Inf', '+Inf', 'NaN'])('takes %s for a value', (value) => {
    expect(parseMetrics(`a ${value}\n`).families[0]?.samples[0]?.value).toBe(value);
  });

  test('ignores a timestamp after the value', () => {
    expect(parseMetrics('a 1 1700000000000\n').families[0]?.samples[0]?.value).toBe('1');
  });

  test.each([
    ['a value that is no number', 'a one'],
    ['a name that starts with a digit', '1a 1'],
    ['a sample without a value', 'a'],
    ['an unterminated label', 'a{k="v} 1'],
    ['a label without quotes', 'a{k=v} 1'],
    ['labels without a comma', 'a{k="v"j="w"} 1'],
    ['a stray comment', '# a comment'],
    ['markup', '<img src=x onerror=alert(1)>'],
    ['a value with trailing text', 'a 1 x'],
  ])('keeps %s apart, as it is', (_, line) => {
    expect(parseMetrics(`${line}\n`)).toEqual({ families: [], other: [line] });
  });

  // A label list that has something in it that is none of a name and a quoted value is not read "as far as it goes".
  test.each([
    ['junk before a label', 'a{!!k="v"} 1'],
    ['junk between labels', 'a{k="v",!!j="w"} 1'],
    ['junk after the last label', 'a{k="v",j="w"!!} 1'],
    ['a label without a name', 'a{="v"} 1'],
  ])('keeps %s apart, as it is', (_, line) => {
    expect(parseMetrics(`${line}\n`)).toEqual({ families: [], other: [line] });
  });

  test('reads the line ends of Windows', () => {
    expect(parseMetrics('# TYPE a gauge\r\na 1\r\n')).toEqual({
      families: [{ name: 'a', help: '', type: 'gauge', samples: [{ labels: [], value: '1' }] }],
      other: [],
    });
  });

  test('skips empty lines', () => {
    expect(parseMetrics('\n\n  \n')).toEqual({ families: [], other: [] });
  });

  test('takes nothing for a family from a line that is kept apart', () => {
    expect(parseMetrics('# TYPE a gauge\na nope\n').families[0]?.samples).toEqual([]);
  });
});
