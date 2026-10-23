// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import encodeQR from '@paulmillr/qr';
import decodeQR from '@paulmillr/qr/decode.js';
import { describe, expect, test } from 'vitest';
import { encode, pathOf, quietZone } from './qr';

/** Rebuilds the modules from the path, so that the tests check what is drawn and not how it is written. */
function modulesOf(path: string, size: number): boolean[][] {
  const modules = Array.from({ length: size }, () => Array.from({ length: size }, () => false));
  for (const [, x, y, run] of path.matchAll(/M(\d+) (\d+)h(\d+)v1h-\d+z/g)) {
    for (let i = 0; i < Number(run); i++) {
      modules[Number(y)]![Number(x) + i] = true;
    }
  }
  return modules;
}

/** Draws the code as an image with the quiet zone, as a screen or a printer would show it. */
function rasterize(text: string, scale = 6) {
  const qr = encode(text)!;
  const modules = modulesOf(qr.path, qr.size);
  const side = (qr.size + 2 * quietZone) * scale;
  const data = new Uint8Array(side * side * 4).fill(255);
  for (let y = 0; y < side; y++) {
    for (let x = 0; x < side; x++) {
      const mx = Math.floor(x / scale) - quietZone;
      const my = Math.floor(y / scale) - quietZone;
      if (modules[my]?.[mx]) {
        const i = (y * side + x) * 4;
        data[i] = data[i + 1] = data[i + 2] = 0;
      }
    }
  }
  return { width: side, height: side, data };
}

describe('the drawn code', () => {
  // The decoder reads the image that a person would scan, so this proves that what is drawn from
  // the path says the text, whatever the encoder and the path code do in between.
  test.each([
    'https://t.example.net/abcdefghijklmnopqrstuvwxyz',
    'https://t.example.net/abcdefghijklmnopqrstuvwxyz.gif',
    'otpauth://totp/Nyktus:ada@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Nyktus',
    'A',
    'https://example.com/pfad/mit/umlauten/%C3%A4%C3%B6%C3%BC?x=1&y=2',
  ])('is read back as %s', (text) => {
    expect(decodeQR(rasterize(text))).toBe(text);
  });

  test('is not read back as another text', () => {
    expect(decodeQR(rasterize('https://a.example/x'))).not.toBe('https://a.example/y');
  });
});

describe('the quiet zone', () => {
  // Readers find a code by the empty margin around it: the standard asks for four modules.
  test('is four modules wide, and the drawn image has it on every side', async () => {
    expect(quietZone).toBeGreaterThanOrEqual(4);
    const { default: QrCode } = await import('./components/QrCode.vue');
    const { mount } = await import('@vue/test-utils');
    const qr = encode('https://t.example.net/abcdefghijklmnopqrstuvwxyz')!;
    const wrapper = mount(QrCode, { props: { text: 'https://t.example.net/abcdefghijklmnopqrstuvwxyz', label: 'code' } });
    const side = qr.size + 2 * quietZone;
    expect(wrapper.get('svg').attributes('viewBox')).toBe(`${-quietZone} ${-quietZone} ${side} ${side}`);
  });
});

describe('pathOf', () => {
  test('joins the dark modules of a row into runs', () => {
    expect(
      pathOf([
        [true, true, false, true],
        [false, false, false, false],
        [false, true, true, true],
      ]),
    ).toBe('M0 0h2v1h-2zM3 0h1v1h-1zM1 2h3v1h-3z');
  });

  test('draws nothing for a code without dark modules', () => {
    expect(pathOf([[false, false]])).toBe('');
  });
});

describe('encode', () => {
  const url = 'https://t.example.net/abcdefghijklmnopqrstuvwxyz';

  test('draws what the library encoded, module for module', () => {
    const qr = encode(url);
    expect(qr).toBeDefined();
    const reference = encodeQR(url, 'raw', { ecc: 'medium', border: 0 });
    expect(modulesOf(qr!.path, qr!.size)).toEqual(reference);
  });

  // Every code has the same three finder patterns and the timing patterns between them, which
  // is how a reader finds and aligns it; a code without them is not a QR code.
  test('has the finder and timing patterns that readers look for', () => {
    const qr = encode(url)!;
    const m = modulesOf(qr.path, qr.size);
    const finder = (x0: number, y0: number) => {
      for (let y = 0; y < 7; y++) {
        for (let x = 0; x < 7; x++) {
          const ring = x === 0 || x === 6 || y === 0 || y === 6;
          const core = x >= 2 && x <= 4 && y >= 2 && y <= 4;
          expect(m[y0 + y]![x0 + x], `finder at ${x0},${y0} module ${x},${y}`).toBe(ring || core);
        }
      }
    };
    finder(0, 0);
    finder(qr.size - 7, 0);
    finder(0, qr.size - 7);
    for (let i = 8; i < qr.size - 8; i++) {
      expect(m[6]![i], `timing row ${i}`).toBe(i % 2 === 0);
      expect(m[i]![6], `timing column ${i}`).toBe(i % 2 === 0);
    }
  });

  test('uses the size that fits the text', () => {
    expect(encode('a')!.size).toBe(21);
    expect(encode(url)!.size).toBeGreaterThan(21);
    expect((encode(url)!.size - 17) % 4).toBe(0);
  });

  test('keeps the error correction at medium, which the reader needs for a printed code', () => {
    // The same text at another level yields another code.
    const medium = encode(url)!;
    const low = encodeQR(url, 'raw', { ecc: 'low', border: 0 });
    expect(modulesOf(medium.path, medium.size)).not.toEqual(low);
  });

  test('returns nothing for text that is too long for a code', () => {
    expect(encode('x'.repeat(5000))).toBeUndefined();
  });
});
