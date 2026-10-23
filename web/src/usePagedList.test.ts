// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, test, vi } from 'vitest';
import { ApiError } from './api/errors';
import { usePagedList } from './usePagedList';

describe('usePagedList', () => {
  test('loads a page and the next one after it, with the cursor', async () => {
    const fetchPage = vi
      .fn()
      .mockResolvedValueOnce({ items: ['a', 'b'], next: 'c1' })
      .mockResolvedValueOnce({ items: ['c'], next: undefined });
    const list = usePagedList<string>(fetchPage);
    await list.reload();
    expect(list.items.value).toEqual(['a', 'b']);
    expect(list.next.value).toBe('c1');
    await list.more();
    expect(fetchPage).toHaveBeenLastCalledWith('c1');
    expect(list.items.value).toEqual(['a', 'b', 'c']);
    expect(list.next.value).toBeUndefined();
    await list.more();
    expect(fetchPage).toHaveBeenCalledTimes(2);
  });

  test('starts again from the first page on a reload', async () => {
    const fetchPage = vi.fn().mockResolvedValue({ items: ['a'], next: 'c1' });
    const list = usePagedList<string>(fetchPage);
    await list.reload();
    await list.more();
    await list.reload();
    expect(list.items.value).toEqual(['a']);
    expect(fetchPage).toHaveBeenLastCalledWith(undefined);
  });

  // A slow answer for a filter that has been changed must not replace the list of the new filter.
  test('drops a slow answer that a newer load has replaced', async () => {
    let releaseOld: (page: { items: string[]; next: undefined }) => void = () => undefined;
    const fetchPage = vi
      .fn()
      .mockImplementationOnce(() => new Promise((resolve) => (releaseOld = resolve)))
      .mockResolvedValueOnce({ items: ['new'], next: undefined });
    const list = usePagedList<string>(fetchPage);
    const old = list.reload();
    await list.reload();
    releaseOld({ items: ['old'], next: undefined });
    await old;
    expect(list.items.value).toEqual(['new']);
    expect(list.loading.value).toBe(false);
  });

  test('shows nothing of the filter before when a reload fails, and has no cursor left', async () => {
    const fetchPage = vi
      .fn()
      .mockResolvedValueOnce({ items: ['a'], next: 'c1' })
      .mockRejectedValueOnce(new ApiError('unavailable', 503));
    const list = usePagedList<string>(fetchPage);
    await list.reload();
    await list.reload();
    expect(list.items.value).toEqual([]);
    expect(list.next.value).toBeUndefined();
    expect(list.loaded.value).toBe(false);
    expect(list.error.value).toBe('The server is busy. Try again in a moment.');
    await list.more();
    expect(fetchPage).toHaveBeenCalledTimes(2);
  });

  test('keeps what it has when a later page fails, and says so', async () => {
    const fetchPage = vi
      .fn()
      .mockResolvedValueOnce({ items: ['a'], next: 'c1' })
      .mockRejectedValueOnce(new ApiError('unavailable', 503));
    const list = usePagedList<string>(fetchPage);
    await list.reload();
    await list.more();
    expect(list.items.value).toEqual(['a']);
    expect(list.error.value).toBe('The server is busy. Try again in a moment.');
    expect(list.next.value).toBe('c1');
    expect(list.loading.value).toBe(false);
  });
});
