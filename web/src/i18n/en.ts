// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * The English texts are the reference: de.ts must have exactly these keys and
 * the same placeholders, so a missing text is an error of the type check.
 */
export const en = {
  'app.skipToContent': 'Skip to content',
  'app.loading': 'Loading \u2026',

  'nav.label': 'Main navigation',
  'nav.overview': 'Overview',

  'menu.label': 'Account',
  'menu.signOut': 'Sign out',
  'menu.language': 'Language',

  'role.admin': 'Administrator',
  'role.user': 'User',
  'role.viewer': 'Viewer',

  'home.title': 'Overview',
  'home.welcome': 'Signed in as {name}.',
  'home.role': 'Role: {role}',

  'app.saving': 'Saving \u2026',

  'field.email': 'Email address',
  'field.displayName': 'Display name',
  'field.nameRequired': 'Enter a name.',

  'password.new': 'New password',
  'password.repeat': 'Repeat the password',
  'password.hint': 'Between {min} and {max} characters.',
  'password.too_short': 'The password needs at least {min} characters.',
  'password.too_long': 'The password can have at most {max} characters.',
  'password.mismatch': 'The two passwords are not the same.',

  'link.invalid': 'This link is not valid. It may have expired or been used already. Ask for a new one.',
  'link.toSignIn': 'Go to sign-in',

  'setup.title': 'Set up Nyktus',
  'setup.intro': 'Create the first administrator.',
  'setup.invalid':
    'This setup link is not valid. It may have expired or been used already, or the installation is set up. The operator can restart the console to get a new link.',
  'setup.submit': 'Create administrator',
  'setup.done': 'The administrator has been created. You can sign in now.',

  'activate.title': 'Activate your account',
  'activate.intro': 'Choose a password for your account.',
  'activate.submit': 'Activate account',
  'activate.done': 'Your account is active. Sign in with your email address and the new password.',

  'reset.title': 'Choose a new password',
  'reset.intro': 'Choose a new password for your account.',
  'reset.submit': 'Change password',
  'reset.done': 'The password has been changed. Sign in with the new password.',

  'notFound.title': 'Page not found',
  'notFound.body': 'There is no page at this address.',
  'notFound.back': 'Back to the overview',

  'signIn.title': 'Sign in',
  'signIn.password': 'Password',
  'signIn.submit': 'Sign in',
  'signIn.submitting': 'Signing in \u2026',
  'signIn.sso': 'Sign in with SSO',
  'signIn.ssoUnavailable': 'Sign in with SSO is not available at the moment.',
  'signIn.or': 'or',
  'signIn.loadFailed': 'The sign-in options could not be loaded.',
  'signIn.retry': 'Try again',
  'session.unavailable.title': 'Cannot check your session',
  'session.unavailable.body': 'The server did not answer, so the console cannot tell whether you are still signed in. Your session may be valid. Try again in a moment.',
  'session.retry': 'Try again',
  'signIn.noMethod': 'No sign-in method is enabled on this server.',

  'secondFactor.title': 'Second factor',
  'secondFactor.intro': 'Enter the code of your authenticator app.',
  'secondFactor.code': 'Code',
  'secondFactor.recoveryIntro': 'Enter one of your recovery codes. Each one works once.',
  'secondFactor.recoveryCode': 'Recovery code',
  'secondFactor.useRecovery': 'Use a recovery code',
  'secondFactor.useCode': 'Use the code of the app',
  'secondFactor.submit': 'Continue',
  'secondFactor.back': 'Start again',

  'error.invalid_credentials': 'The email address or the password is wrong.',
  'error.invalid_code': 'The code is not valid.',
  'error.invalid_challenge': 'The sign-in has expired. Enter your email address and password again.',
  'error.account_locked': 'The account is locked. Try again in {duration}.',
  'error.cross_origin':
    'This page was opened at {origin}, which is not the address that the server expects. Open the console at the address that the operator configured as NYKTUS_CONSOLE_URL.',
  'error.unauthenticated': 'Your session has ended. Sign in again.',
  'error.forbidden': 'You are not allowed to do this.',
  'error.invalid_request': 'The input is not valid.',
  'error.not_found': 'This does not exist.',
  'error.rate_limited': 'Too many requests. Try again in a moment.',
  'error.unavailable': 'The server is busy. Try again in a moment.',
  'error.server': 'Something went wrong on the server.',
  'error.network': 'The server could not be reached.',
  'error.sso': 'Signing in with SSO failed. Try again, or ask an administrator.',
} as const;

export type MessageKey = keyof typeof en;
