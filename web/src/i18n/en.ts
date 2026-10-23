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

  'nav.honeytokens': 'Honeytokens',

  'common.save': 'Save',
  'common.cancel': 'Cancel',
  'common.delete': 'Delete',
  'common.loadMore': 'Load more',
  'common.copy': 'Copy',
  'common.copied': 'Copied',
  'common.none': 'None',
  'common.all': 'All',
  'common.saved': 'Saved.',

  'state.enabled': 'Enabled',
  'state.disabled': 'Disabled',

  'severity.low': 'Low',
  'severity.medium': 'Medium',
  'severity.high': 'High',
  'severity.critical': 'Critical',
  'severity.default': 'Default of the type',

  'field.name': 'Name',
  'field.notes': 'Notes',
  'field.enabled': 'Enabled',
  'field.state': 'State',
  'field.severity': 'Severity',
  'field.techniques': 'Techniques',
  'field.type': 'Type',
  'field.scenario': 'Scenario',
  'field.created': 'Created',
  'field.updated': 'Updated',

  'forbidden.title': 'Not allowed',
  'forbidden.body': 'Your role does not allow you to open this page.',

  'honeytokens.title': 'Honeytokens',
  'honeytokens.intro': 'A honeytoken raises an event when someone requests its URL or resolves its name.',
  'honeytokens.new': 'New honeytoken',
  'honeytokens.empty': 'There are no honeytokens yet.',
  'honeytokens.emptyFiltered': 'No honeytoken matches the filter.',
  'honeytokens.loadFailed': 'The honeytokens could not be loaded.',
  'honeytokens.back': 'All honeytokens',
  'honeytokens.standsAlone': 'Stands alone',
  'honeytokens.change': 'Change',
  'honeytokens.create.title': 'New honeytoken',
  'honeytokens.create.submit': 'Create honeytoken',
  'honeytokens.created': 'The honeytoken has been created. Place its URL where an attacker would find it.',
  'honeytokens.redirect': 'Redirect to',
  'honeytokens.redirectHint': 'Where the URL leads. Without one, the trigger uses its default target.',
  'honeytokens.notesHint': 'Where and why it is placed.',
  'honeytokens.techniquesHint': 'Identifiers of MITRE ATT&CK techniques, separated by commas, such as T1078 or T1003.001.',
  'honeytokens.techniquesInvalid': 'These are not technique identifiers: {values}',
  'honeytokens.typeFixed': 'The type cannot be changed.',
  'honeytokens.place.title': 'Place this',
  'honeytokens.place.fixed': 'The value cannot be changed. To replace one that has been exposed, create a new honeytoken and delete this one.',
  'honeytokens.qr.label': 'QR code of the URL of the honeytoken',
  'honeytokens.qr.hint': 'Print it or show it where someone would scan it. Whoever opens the URL raises an event.',
  'honeytokens.delete.title': 'Delete this honeytoken?',
  'honeytokens.delete.body':
    'Its URL stops raising events, and the trigger answers it like any unknown URL. Remove the placed URL as well, so that it does not mislead your own team.',
  'honeytokens.delete.confirm': 'Delete honeytoken',
  'honeytokens.filter.type': 'Type',
  'honeytokens.filter.state': 'State',

  'honeytokenType.web_url': 'Web URL',
  'honeytokenType.web_image': 'Web image',
  'honeytokenType.dns': 'DNS name',
  'honeytokenType.web_url.hint': 'Raises an event when the URL is opened, for example through a link or a QR code, and redirects the browser.',
  'honeytokenType.web_image.hint': 'Raises an event when the URL is loaded as an image, for example when a document or mail that embeds it is opened.',
  'honeytokenType.dns.hint': 'Raises an event when one of its names is resolved, for example by a tool that connects to a host named in a file.',

  'error.conflict': 'The request conflicts with the current state. Reload the page and try again.',
  'error.unprocessable': 'The request cannot be carried out.',
  'error.dns_not_configured': 'DNS honeytokens need a zone of the DNS role. The operator sets it with NYKTUS_DNS_ZONES.',
} as const;

export type MessageKey = keyof typeof en;
