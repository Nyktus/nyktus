// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

export type Segment = { kind: 'text'; text: string } | { kind: 'hidden'; label: string };

/**
 * Characters that draw nothing or change how the text around them is drawn. The
 * server replaces most of them in what an attacker sent, but keeps the graphic ones
 * that show nothing, because removing them would damage legitimate text; here they
 * are made visible. So are the spaces other than U+0020, which look like it: a user name
 * with a no-break space after it is not the user name without. Control and format characters are listed as well, so that the
 * page does not depend on the server having removed them.
 */
const hidden =
  /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}\u{180B}-\u{180D}\u{17B4}\u{17B5}\u{3164}\u{115F}\u{1160}\u{2800}\u{034F}\u{FFA0}]|(?!\u0020)\p{Zs}/u;

/** The marker for a character that shows nothing, such as U+3164 between angle quotes. */
function marker(character: string): string {
  const hex = (character.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0');
  return `\u2039U+${hex}\u203A`;
}

/** Splits text into the runs that are drawn as they are and the characters that are replaced by a marker. */
export function segments(value: string): Segment[] {
  const out: Segment[] = [];
  let run = '';
  for (const character of value) {
    if (hidden.test(character)) {
      if (run !== '') {
        out.push({ kind: 'text', text: run });
        run = '';
      }
      out.push({ kind: 'hidden', label: marker(character) });
    } else {
      run += character;
    }
  }
  if (run !== '') {
    out.push({ kind: 'text', text: run });
  }
  return out;
}
