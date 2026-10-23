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
    case 'unprocessable':
      return t('error.unprocessable');
    case 'dns_not_configured':
      return t('error.dns_not_configured');
    case 'artifact_reveals_decoy':
      return t('error.artifact_reveals_decoy');
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
