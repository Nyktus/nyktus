// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { mount } from '@vue/test-utils';
import { describe, expect, test } from 'vitest';
import MarkdownView from './components/MarkdownView';
import { maxSource, parseInline, parseMarkdown } from './markdown';

const text = (s: string) => ({ kind: 'text', text: s });
const item = (s: string, blocks: unknown[] = []) => ({ children: [text(s)], blocks });

describe('parseMarkdown', () => {
  test('reads headings, paragraphs and the lines of a paragraph as one', () => {
    expect(parseMarkdown('# Title\n\nFirst line\nsecond line\n\n## Part')).toEqual([
      { kind: 'heading', level: 1, children: [text('Title')] },
      { kind: 'paragraph', children: [text('First line second line')] },
      { kind: 'heading', level: 2, children: [text('Part')] },
    ]);
  });

  test('reads unordered and ordered lists, with continuation lines', () => {
    expect(parseMarkdown('- one\n- two\n  continued\n\n1. first\n2. second')).toEqual([
      { kind: 'list', ordered: false, items: [item('one'), item('two continued')] },
      { kind: 'list', ordered: true, items: [item('first'), item('second')] },
    ]);
  });

  test('keeps a code block as it is, and ends an unclosed one at the end', () => {
    expect(parseMarkdown('```sh\ncurl <url> # **not bold**\n\n  indented\n```\nafter')).toEqual([
      { kind: 'code', text: 'curl <url> # **not bold**\n\n  indented' },
      { kind: 'paragraph', children: [text('after')] },
    ]);
    expect(parseMarkdown('```\nunclosed')).toEqual([{ kind: 'code', text: 'unclosed' }]);
  });

  test('reads quotes', () => {
    expect(parseMarkdown('> a\n> b')).toEqual([{ kind: 'quote', children: [text('a b')] }]);
  });

  test('reads the line ends of Windows and old Macs', () => {
    expect(parseMarkdown('# A\r\n\r\ntext\rmore')).toEqual([
      { kind: 'heading', level: 1, children: [text('A')] },
      { kind: 'paragraph', children: [text('text more')] },
    ]);
  });

  test.each([
    ['# Title #', 'Title'],
    ['## Title ##   ', 'Title'],
    ['## Use C#', 'Use C#'],
    ['# Tracking #1', 'Tracking #1'],
    ['###   spaced   ', 'spaced'],
    ['# #', ''],
  ])('reads the heading %j as %j, with a closing sequence only after a space', (line, want) => {
    const [block] = parseMarkdown(line);
    expect(block).toMatchObject({ kind: 'heading', children: want === '' ? [] : [text(want)] });
  });

  test('keeps a code block below the item of a list with that item, as it is written there', () => {
    expect(parseMarkdown('1. Press\n2. Write between the braces:\n\n   ```\n   INCLUDE "x" \\d\n     more\n   ```\n\n   The `\\d` keeps it.\n3. Save')).toEqual([
      {
        kind: 'list',
        ordered: true,
        items: [item('Press'), item('Write between the braces:', [{ kind: 'code', text: 'INCLUDE "x" \\d\n  more' }, { kind: 'paragraph', children: [text('The '), { kind: 'code', text: '\\d' }, text(' keeps it.')] }]), item('Save')],
      },
    ]);
  });

  test('draws a code block below an item inside the item', () => {
    const wrapper = mount(MarkdownView, { props: { source: '1. Write:\n   ```\n   a <b>\n   ```\n2. Next' } });
    expect(wrapper.findAll('li')).toHaveLength(2);
    expect(wrapper.get('li pre code').text()).toBe('a <b>');
    expect(wrapper.find('b').exists()).toBe(false);
  });

  test('shows a text that is longer than it reads as it is, in one block', () => {
    const long = `# not a heading ${'x'.repeat(maxSource)}`;
    expect(parseMarkdown(long)).toEqual([{ kind: 'code', text: long }]);
  });

  // The patterns that look ahead for a closing mark must not read to the end of the text from
  // every opener. The sizes are such that the slow patterns took seconds, and these take milliseconds.
  test.each([
    ['a heading with spaces in it', `# a${' '.repeat(6000)}b`],
    ['stars that never close', '*a '.repeat(20000)],
    ['double stars that never close', '**a '.repeat(15000)],
    ['underscores that never close', ' _a'.repeat(20000)],
    ['brackets that never close', '[a'.repeat(30000)],
    ['links that never close', '[a](('.repeat(15000)],
    ['backticks', '`a '.repeat(20000)],
  ])('is quick for %s', (_name, source) => {
    const started = performance.now();
    parseMarkdown(source);
    expect(performance.now() - started).toBeLessThan(1000);
  });

  test('has nothing for nothing', () => {
    expect(parseMarkdown('')).toEqual([]);
    expect(parseMarkdown('\n \n')).toEqual([]);
  });

  test('keeps what it does not know as text, such as a table', () => {
    expect(parseMarkdown('| a | b |')).toEqual([{ kind: 'paragraph', children: [text('| a | b |')] }]);
  });
});

describe('parseInline', () => {
  test('does not read an underscore inside a word as emphasis, as in a name with underscores', () => {
    expect(parseInline('the file my_config_file and snake_case_name')).toEqual([text('the file my_config_file and snake_case_name')]);
    expect(parseInline('is _meant_ here')).toEqual([text('is '), { kind: 'em', children: [text('meant')] }, text(' here')]);
  });

  test('reads code, emphasis and links', () => {
    expect(parseInline('a `b` **c** *d* _e_ [f](https://example.com/x)')).toEqual([
      text('a '),
      { kind: 'code', text: 'b' },
      text(' '),
      { kind: 'strong', children: [text('c')] },
      text(' '),
      { kind: 'em', children: [text('d')] },
      text(' '),
      { kind: 'em', children: [text('e')] },
      text(' '),
      { kind: 'link', href: 'https://example.com/x', children: [text('f')] },
    ]);
  });

  test('takes nothing inside code as emphasis', () => {
    expect(parseInline('`**x**`')).toEqual([{ kind: 'code', text: '**x**' }]);
  });

  test('leaves the underscores of a name alone', () => {
    expect(parseInline('NYKTUS_CONSOLE_URL and snake_case_name')).toEqual([text('NYKTUS_CONSOLE_URL and snake_case_name')]);
  });

  test('leaves a lone star or a star between spaces alone', () => {
    expect(parseInline('2 * 3 * 4 and a*')).toEqual([text('2 * 3 * 4 and a*')]);
  });

  // A link is made only for an address that a browser opens as a page of the web.
  test.each(['javascript:alert(1)', 'data:text/html,<script>', 'vbscript:x', '//evil.example', '/relative', 'ftp://x.example/', 'https://a b.example', ''])(
    'makes no link of %j, and keeps its text',
    (href) => {
      expect(parseInline(`[click](${href})`)).toEqual([text('click')]);
    },
  );

  test('makes a link of an address with http', () => {
    expect(parseInline('[x](http://example.com)')).toEqual([{ kind: 'link', href: 'http://example.com/', children: [text('x')] }]);
  });
});

describe('MarkdownView', () => {
  const draw = (source: string) => mount(MarkdownView, { props: { source } });

  test('draws elements, with the headings of a guide below the heading of the page', () => {
    const wrapper = draw('## Title\n\n### Part\n\n- one\n\n1. first\n\n```\ncode\n```');
    expect(wrapper.get('h2').text()).toBe('Title');
    expect(wrapper.get('h3').text()).toBe('Part');
    expect(wrapper.find('h1').exists()).toBe(false);
    expect(wrapper.get('ul li').text()).toBe('one');
    expect(wrapper.get('ol li').text()).toBe('first');
    expect(wrapper.get('pre code').text()).toBe('code');
  });

  // The text is untrusted by rule: a guide names values that someone typed.
  test('shows HTML in the text as text', () => {
    const wrapper = draw('<img src=x onerror=alert(1)> and <script>alert(2)</script>\n\n- <b>x</b>\n\n```\n<svg onload=alert(3)>\n```\n\n`<u>y</u>`');
    expect(wrapper.find('img').exists()).toBe(false);
    expect(wrapper.find('script').exists()).toBe(false);
    expect(wrapper.find('b').exists()).toBe(false);
    expect(wrapper.find('svg').exists()).toBe(false);
    expect(wrapper.find('u').exists()).toBe(false);
    expect(wrapper.text()).toContain('<img src=x onerror=alert(1)>');
    expect(wrapper.get('pre').text()).toBe('<svg onload=alert(3)>');
  });

  test('opens a link in a new window that knows nothing of the console', () => {
    const a = draw('[docs](https://example.com/docs)').get('a');
    expect(a.attributes('href')).toBe('https://example.com/docs');
    expect(a.attributes('target')).toBe('_blank');
    expect(a.attributes('rel')).toBe('noopener noreferrer');
  });

  test('draws no link for a script address', () => {
    const wrapper = draw('[x](javascript:alert(1))');
    expect(wrapper.find('a').exists()).toBe(false);
    expect(wrapper.text()).toBe('x');
  });
});
