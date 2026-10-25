// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * What a failed request means for the user. The console shows a fixed, translated
 * text for each kind and never the message of the server: a message can carry text
 * that an attacker chose, and the kind says all that the user can act on.
 */
export type ErrorKind =
  | 'invalid_credentials'
  | 'invalid_code'
  | 'invalid_challenge'
  | 'account_locked'
  | 'cross_origin'
  | 'wrong_password'
  | 'wrong_code'
  | 'invalid_state'
  | 'email_taken'
  | 'last_active_admin'
  | 'own_account'
  | 'oidc_account'
  | 'too_many_api_keys'
  | 'totp_enabled'
  | 'totp_not_enabled'
  | 'no_totp_setup'
  | 'name_taken'
  | 'too_many_alert_channels'
  | 'alert_channel_enabled'
  | 'test_pending'
  | 'delivery_not_dead'
  | 'persona_conflict'
  | 'deception_already_added'
  | 'scenario_limit'
  | 'target_not_allowed'
  | 'header_not_allowed'
  | 'url_not_allowed'
  | 'recipients_not_allowed'
  | 'reauthentication_required'
  | 'unauthenticated'
  | 'forbidden'
  | 'invalid_request'
  | 'not_found'
  | 'conflict'
  | 'unprocessable'
  | 'dns_not_configured'
  | 'artifact_reveals_decoy'
  | 'rate_limited'
  | 'unavailable'
  | 'server'
  | 'network';

export class ApiError extends Error {
  readonly kind: ErrorKind;
  readonly status: number;
  /** Seconds until a lock or a limit ends, as the server reported it. */
  readonly retryAfter: number | undefined;

  constructor(kind: ErrorKind, status: number, retryAfter?: number) {
    super(`request failed: ${kind}`);
    this.name = 'ApiError';
    this.kind = kind;
    this.status = status;
    this.retryAfter = retryAfter;
  }
}

/** The codes by which the server tells the kinds of a status apart. */
const codes: Record<number, Partial<Record<string, ErrorKind>>> = {
  401: {
    invalid_credentials: 'invalid_credentials',
    invalid_code: 'invalid_code',
    invalid_challenge: 'invalid_challenge',
    unauthenticated: 'unauthenticated',
  },
  403: {
    account_locked: 'account_locked',
    cross_origin: 'cross_origin',
    wrong_password: 'wrong_password',
    wrong_code: 'wrong_code',
    reauthentication_required: 'reauthentication_required',
  },
  409: {
    invalid_state: 'invalid_state',
    email_taken: 'email_taken',
    last_active_admin: 'last_active_admin',
    own_account: 'own_account',
    oidc_account: 'oidc_account',
    too_many_api_keys: 'too_many_api_keys',
    totp_enabled: 'totp_enabled',
    totp_not_enabled: 'totp_not_enabled',
    no_totp_setup: 'no_totp_setup',
    name_taken: 'name_taken',
    too_many_alert_channels: 'too_many_alert_channels',
    alert_channel_enabled: 'alert_channel_enabled',
    test_pending: 'test_pending',
    delivery_not_dead: 'delivery_not_dead',
    persona_conflict: 'persona_conflict',
    deception_already_added: 'deception_already_added',
    scenario_limit: 'scenario_limit',
  },
  422: {
    dns_not_configured: 'dns_not_configured',
    artifact_reveals_decoy: 'artifact_reveals_decoy',
    target_not_allowed: 'target_not_allowed',
    header_not_allowed: 'header_not_allowed',
    url_not_allowed: 'url_not_allowed',
    recipients_not_allowed: 'recipients_not_allowed',
  },
};

/**
 * Maps the status of a response and the code of its body, if it has one, to a
 * kind. An unknown code falls back to the kind of its status, so that a code that
 * the server adds later is still handled.
 */
export function classify(status: number, code: string | undefined): ErrorKind {
  const known = code === undefined ? undefined : codes[status]?.[code];
  if (known !== undefined) {
    return known;
  }
  switch (status) {
    case 401:
      return 'unauthenticated';
    case 403:
      return 'forbidden';
    case 400:
    case 413:
    case 415:
      return 'invalid_request';
    case 404:
      return 'not_found';
    case 409:
      return 'conflict';
    case 422:
      return 'unprocessable';
    case 429:
      return 'rate_limited';
    case 503:
      return 'unavailable';
    default:
      return 'server';
  }
}
