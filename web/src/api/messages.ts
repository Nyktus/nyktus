// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { formatMinutes, t } from '../i18n';
import type { ApiError } from './errors';

/** How long a lock lasts when the server does not say; it is the fixed lock of 15 minutes. */
const defaultLockSeconds = 15 * 60;

/**
 * Returns the text for a failed request. Every text is fixed and translated; the
 * response of the server contributes nothing but its kind and a number.
 */
export function errorText(error: ApiError): string {
  switch (error.kind) {
    case 'invalid_credentials':
      return t('error.invalid_credentials');
    case 'invalid_code':
      return t('error.invalid_code');
    case 'invalid_challenge':
      return t('error.invalid_challenge');
    case 'account_locked':
      return t('error.account_locked', { duration: formatMinutes(error.retryAfter ?? defaultLockSeconds) });
    case 'cross_origin':
      return t('error.cross_origin', { origin: globalThis.location.origin });
    case 'unauthenticated':
      return t('error.unauthenticated');
    case 'invalid_request':
      return t('error.invalid_request');
    case 'not_found':
      return t('error.not_found');
    case 'conflict':
      return t('error.conflict');
    case 'invalid_state':
      return t('error.invalid_state');
    case 'email_taken':
      return t('error.email_taken');
    case 'last_active_admin':
      return t('error.last_active_admin');
    case 'own_account':
      return t('error.own_account');
    case 'oidc_account':
      return t('error.oidc_account');
    case 'too_many_api_keys':
      return t('error.too_many_api_keys');
    case 'totp_enabled':
      return t('error.totp_enabled');
    case 'totp_not_enabled':
      return t('error.totp_not_enabled');
    case 'no_totp_setup':
      return t('error.no_totp_setup');
    case 'name_taken':
      return t('error.name_taken');
    case 'too_many_alert_channels':
      return t('error.too_many_alert_channels');
    case 'alert_channel_enabled':
      return t('error.alert_channel_enabled');
    case 'test_pending':
      return t('error.test_pending');
    case 'delivery_not_dead':
      return t('error.delivery_not_dead');
    case 'deception_already_added':
      return t('error.deception_already_added');
    case 'target_not_allowed':
      return t('error.target_not_allowed');
    case 'header_not_allowed':
      return t('error.header_not_allowed');
    case 'url_not_allowed':
      return t('error.url_not_allowed');
    case 'recipients_not_allowed':
      return t('error.recipients_not_allowed');
    case 'unprocessable':
      return t('error.unprocessable');
    case 'dns_not_configured':
      return t('error.dns_not_configured');
    case 'rate_limited':
      return t('error.rate_limited');
    case 'unavailable':
      return t('error.unavailable');
    case 'network':
      return t('error.network');
    case 'server':
      return t('error.server');
    case 'forbidden':
    case 'wrong_password':
    case 'wrong_code':
    case 'reauthentication_required':
      return t('error.forbidden');
  }
}
