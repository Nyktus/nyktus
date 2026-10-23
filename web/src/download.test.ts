// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { afterEach, expect, test, vi } from 'vitest';
import { saveFile } from './download';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
  document.body.innerHTML = '';
});

// A file is handed to the browser by a link that the console makes; it is never navigated to,
// and the address that was made for it does not outlive the download.
test('hands the file to the browser under the name it was given, without opening it', () => {
  vi.useFakeTimers({ toFake: ['setTimeout'] });
  const created = vi.fn(() => 'blob:console/1');
  const revoked = vi.fn();
  vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: created, revokeObjectURL: revoked }));
  const clicked: { download: string; href: string; rel: string; target: string }[] = [];
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
    clicked.push({ download: this.download, href: this.href, rel: this.rel, target: this.target });
  });
  saveFile(new Blob(['<html>']), 'bookmarks.html');
  expect(clicked).toEqual([{ download: 'bookmarks.html', href: 'blob:console/1', rel: 'noopener', target: '' }]);
  expect(document.body.querySelectorAll('a')).toHaveLength(0);
  expect(revoked).not.toHaveBeenCalled();
  vi.advanceTimersByTime(10_000);
  expect(revoked).toHaveBeenCalledWith('blob:console/1');
});
