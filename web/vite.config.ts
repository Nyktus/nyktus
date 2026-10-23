// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import vue from '@vitejs/plugin-vue';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [vue()],
  build: {
    outDir: 'dist',
    // The directory holds a placeholder that the build must not remove; the
    // Makefile empties the directory before it builds.
    emptyOutDir: false,
    sourcemap: false,
    target: 'es2022',
    // Nothing is inlined as a data: URL, which the content security policy
    // does not allow, and the page loads no script of the build's own besides
    // its files.
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
  },
  test: {
    environment: 'happy-dom',
    include: ['src/**/*.test.ts', 'tests/**/*.test.ts'],
    setupFiles: ['src/testing/warm.ts'],
  },
});
