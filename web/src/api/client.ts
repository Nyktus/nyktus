// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, classify } from './errors';
import { operations, type OperationId, type OperationTypes } from './generated';

type Responses<K extends OperationId> = OperationTypes[K]['responses'];

/** The successful response of an operation: its status and the body that belongs to it. */
export type Result<K extends OperationId> = {
  [S in keyof Responses<K> & number]: { status: S; body: Responses<K>[S] };
}[keyof Responses<K> & number];

type Empty<T> = [T] extends [Record<string, never>] ? true : false;

/** The arguments of an operation: only what it takes, and what it needs is required. */
type Args<K extends OperationId> = (Empty<OperationTypes[K]['path']> extends true
  ? { path?: undefined }
  : { path: OperationTypes[K]['path'] }) &
  (Empty<OperationTypes[K]['query']> extends true ? { query?: undefined } : { query?: OperationTypes[K]['query'] }) &
  (OperationTypes[K]['body'] extends undefined ? { body?: undefined } : { body: OperationTypes[K]['body'] });

export type Fetch = (input: string, init: RequestInit) => Promise<Response>;

export interface ClientOptions {
  fetch: Fetch;
  /**
   * Called when a request that needs a session answers that there is none, so
   * that the console can show the sign-in page. It is not called for the
   * operations that are public, whose 401 means a wrong password.
   */
  onUnauthenticated?: () => void;
  /** How long a request may take, in milliseconds. */
  timeout?: number;
}

const requestTimeout = 30_000;

/** The one place that sends requests. Everything else goes through call. */
export function createClient(options: ClientOptions) {
  async function call<K extends OperationId>(operation: K, args: Args<K>): Promise<Result<K>> {
    const info = operations[operation];
    if (info.navigation) {
      throw new Error(`${operation} is a navigation, not a request`);
    }
    const path = (info.path as string).replace(/\{([A-Za-z_]+)\}/g, (_, name: string) => {
      const value = (args.path as Record<string, string> | undefined)?.[name];
      if (value === undefined) {
        throw new Error(`${operation}: the path parameter ${name} is missing`);
      }
      return encodeURIComponent(value);
    });
    const query = new URLSearchParams();
    for (const [name, value] of Object.entries((args.query ?? {}) as Record<string, unknown>)) {
      if (value !== undefined) {
        query.set(name, String(value));
      }
    }
    const url = query.size > 0 ? `${path}?${query.toString()}` : path;

    const headers: Record<string, string> = { Accept: 'application/json' };
    const init: RequestInit = {
      method: info.method,
      headers,
      // The session travels in a cookie that scripts cannot read. Credentials are
      // sent to this origin only, and a redirect is an error: no operation of the
      // API redirects, and a redirect must not take the cookie elsewhere.
      credentials: 'same-origin',
      redirect: 'error',
      cache: 'no-store',
      signal: AbortSignal.timeout(options.timeout ?? requestTimeout),
    };
    if (args.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(args.body);
    }

    let response: Response;
    try {
      response = await options.fetch(url, init);
    } catch {
      throw new ApiError('network', 0);
    }

    if (response.ok) {
      const status = response.status;
      return { status, body: await readBody(response, info.binary) } as Result<K>;
    }

    const failure = await readError(response);
    const error = new ApiError(classify(response.status, failure.code), response.status, failure.retryAfter);
    if (error.kind === 'unauthenticated' && info.access !== 'public') {
      options.onUnauthenticated?.();
    }
    throw error;
  }

  return { call };
}

/**
 * Reads what a successful response carries: nothing for a 204, the file itself
 * for a download, which is never parsed or shown as markup, and otherwise JSON.
 * What an operation returns is a fact of the specification, not of the response:
 * an answer that is not what the operation promises is a failure.
 */
async function readBody(response: Response, binary: boolean): Promise<unknown> {
  if (response.status === 204) {
    return undefined;
  }
  if (binary) {
    return response.blob();
  }
  try {
    return await response.json();
  } catch {
    throw new ApiError('server', response.status);
  }
}

/**
 * Reads the code of an error body and the delay that the server named. Anything
 * else in the response, such as the page of a proxy, is ignored.
 */
async function readError(response: Response): Promise<{ code: string | undefined; retryAfter: number | undefined }> {
  let code: string | undefined;
  try {
    const body: unknown = await response.json();
    const error = (body as { error?: { code?: unknown } } | null)?.error;
    if (typeof error?.code === 'string') {
      code = error.code;
    }
  } catch {
    // The body is not ours.
  }
  const header = response.headers.get('Retry-After');
  const seconds = header !== null && /^\d{1,7}$/.test(header) ? Number(header) : undefined;
  return { code, retryAfter: seconds };
}

export type Client = ReturnType<typeof createClient>;

let unauthenticated: () => void = () => {};

/** Sets what happens when a request that needs a session finds that there is none. */
export function setUnauthenticatedHandler(handler: () => void): void {
  unauthenticated = handler;
}

/** The client of the console. */
export const api: Client = createClient({
  fetch: (url, init) => fetch(url, init),
  onUnauthenticated: () => {
    unauthenticated();
  },
});
