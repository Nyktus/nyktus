// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { computed, defineComponent, h, type PropType, type VNode } from 'vue';
import { parseMarkdown, type Block, type Inline } from '../markdown';

function inline(parts: Inline[]): (VNode | string)[] {
  return parts.map((part) => {
    switch (part.kind) {
      case 'text':
        return part.text;
      case 'code':
        return h('code', { class: 'mono' }, part.text);
      case 'strong':
        return h('strong', inline(part.children));
      case 'em':
        return h('em', inline(part.children));
      case 'link':
        // A link leaves the console, so it carries nothing of the console along.
        return h('a', { href: part.href, target: '_blank', rel: 'noopener noreferrer' }, inline(part.children));
    }
  });
}

function block(b: Block, top: number): VNode {
  switch (b.kind) {
    case 'heading':
      // The page has headings of its own, so those of a guide start below the one that it stands under.
      return h(`h${Math.min(6, b.level + top)}`, inline(b.children));
    case 'paragraph':
      return h('p', inline(b.children));
    case 'list':
      return h(b.ordered ? 'ol' : 'ul', b.items.map((item) => h('li', [...inline(item.children), ...item.blocks.map((x) => block(x, top))])));
    case 'code':
      return h('pre', { class: 'mono' }, h('code', b.text));
    case 'quote':
      return h('blockquote', inline(b.children));
  }
}

/**
 * Draws Markdown as elements. The text is parsed into a tree and every part is
 * created as a node, so that nothing in it is ever read as HTML.
 */
export default defineComponent({
  name: 'MarkdownView',
  props: {
    source: { type: String as PropType<string>, required: true },
    /** The level of the heading that the guide stands under; the first heading of the guide is one below. */
    under: { type: Number as PropType<number>, default: 1 },
  },
  setup(props) {
    const blocks = computed(() => parseMarkdown(props.source));
    return () => h('div', { class: 'markdown' }, blocks.value.map((b) => block(b, props.under)));
  },
});
