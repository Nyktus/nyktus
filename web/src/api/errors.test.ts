// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, test } from 'vitest';
import { classify, type ErrorKind } from './errors';

describe('classify', () => {
  const cases: [number, string | undefined, ErrorKind][] = [
    [401, 'invalid_credentials', 'invalid_credentials'],
    [401, 'invalid_code', 'invalid_code'],
    [401, 'invalid_challenge', 'invalid_challenge'],
    [401, 'unauthenticated', 'unauthenticated'],
    [401, undefined, 'unauthenticated'],
    [401, 'a_code_that_is_new', 'unauthenticated'],
    [403, 'account_locked', 'account_locked'],
    [403, 'cross_origin', 'cross_origin'],
    [403, 'wrong_password', 'wrong_password'],
    [403, 'wrong_code', 'wrong_code'],
    [403, 'reauthentication_required', 'reauthentication_required'],
    [403, 'forbidden', 'forbidden'],
    [403, undefined, 'forbidden'],
    [400, 'invalid_request', 'invalid_request'],
    [413, undefined, 'invalid_request'],
    [415, undefined, 'invalid_request'],
    [404, 'not_found', 'not_found'],
    [409, 'honeytoken_in_scenario', 'conflict'],
    [409, 'invalid_state', 'invalid_state'],
    [409, 'email_taken', 'email_taken'],
    [409, 'last_active_admin', 'last_active_admin'],
    [409, 'own_account', 'own_account'],
    [409, 'oidc_account', 'oidc_account'],
    [409, 'too_many_api_keys', 'too_many_api_keys'],
    [409, 'totp_enabled', 'totp_enabled'],
    [409, 'totp_not_enabled', 'totp_not_enabled'],
    [409, 'no_totp_setup', 'no_totp_setup'],
    [422, 'own_account', 'unprocessable'],
    [422, 'invalid_state', 'unprocessable'],
    [409, 'name_taken', 'name_taken'],
    [409, 'too_many_alert_channels', 'too_many_alert_channels'],
    [409, 'alert_channel_enabled', 'alert_channel_enabled'],
    [409, 'test_pending', 'test_pending'],
    [409, 'delivery_not_dead', 'delivery_not_dead'],
    [409, 'deception_already_added', 'deception_already_added'],
    [422, 'target_not_allowed', 'target_not_allowed'],
    [422, 'header_not_allowed', 'header_not_allowed'],
    [422, 'url_not_allowed', 'url_not_allowed'],
    [422, 'recipients_not_allowed', 'recipients_not_allowed'],
    [422, 'name_taken', 'unprocessable'],
    [409, 'target_not_allowed', 'conflict'],
    [422, 'dns_not_configured', 'dns_not_configured'],
    [422, 'scenario_not_found', 'unprocessable'],
    [409, 'dns_not_configured', 'conflict'],
    [429, undefined, 'rate_limited'],
    [503, 'unavailable', 'unavailable'],
    [500, 'internal_error', 'server'],
    [502, undefined, 'server'],
  ];
  for (const [status, code, kind] of cases) {
    test(`${status} ${code ?? '(no code)'} is ${kind}`, () => {
      expect(classify(status, code)).toBe(kind);
    });
  }

  test('a code of another status does not change the kind', () => {
    // account_locked is a 403 code; at 401 it says nothing about a lock.
    expect(classify(401, 'account_locked')).toBe('unauthenticated');
    expect(classify(500, 'cross_origin')).toBe('server');
  });
});
