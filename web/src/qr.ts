// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import encodeQR from '@paulmillr/qr';

export interface Qr {
  /** The side of the code in modules, without the quiet zone. */
  size: number;
  /** The dark modules as the path of an SVG with one unit per module. */
  path: string;
}

/** The quiet zone around a code, in modules, that readers need to find it. */
export const quietZone = 4;

/**
 * Encodes text as a QR code, with error correction of the level medium. It
 * returns nothing if the text is too long for a code. The code is drawn from the
 * modules, never as markup that the library made, so that nothing needs to be
 * inserted as HTML.
 */
export function encode(text: string): Qr | undefined {
  let modules: boolean[][];
  try {
    modules = encodeQR(text, 'raw', { ecc: 'medium', border: 0 });
  } catch {
    return undefined;
  }
  return { size: modules.length, path: pathOf(modules) };
}

/** Joins the dark modules of each row into runs, one rectangle for each. */
export function pathOf(modules: boolean[][]): string {
  const parts: string[] = [];
  modules.forEach((row, y) => {
    let x = 0;
    while (x < row.length) {
      if (!row[x]) {
        x++;
        continue;
      }
      const start = x;
      while (x < row.length && row[x]) {
        x++;
      }
      parts.push(`M${start} ${y}h${x - start}v1h-${x - start}z`);
    }
  });
  return parts.join('');
}
