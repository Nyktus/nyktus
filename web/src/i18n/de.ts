// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { MessageKey } from './en';

export const de: Record<MessageKey, string> = {
  'app.skipToContent': 'Zum Inhalt springen',
  'app.loading': 'Wird geladen …',

  'nav.label': 'Hauptnavigation',
  'nav.overview': 'Übersicht',

  'menu.label': 'Konto',
  'menu.signOut': 'Abmelden',
  'menu.language': 'Sprache',

  'role.admin': 'Administrator',
  'role.user': 'Benutzer',
  'role.viewer': 'Leser',

  'home.title': 'Übersicht',
  'home.welcome': 'Angemeldet als {name}.',
  'home.role': 'Rolle: {role}',

  'notFound.title': 'Seite nicht gefunden',
  'notFound.body': 'Unter dieser Adresse gibt es keine Seite.',
  'notFound.back': 'Zurück zur Übersicht',

  'signIn.title': 'Anmelden',
  'signIn.email': 'E-Mail-Adresse',
  'signIn.password': 'Passwort',
  'signIn.submit': 'Anmelden',
  'signIn.submitting': 'Anmeldung läuft …',
  'signIn.sso': 'Mit SSO anmelden',
  'signIn.ssoUnavailable': 'Die Anmeldung mit SSO ist im Moment nicht verfügbar.',
  'signIn.or': 'oder',
  'signIn.loadFailed': 'Die Anmeldeoptionen konnten nicht geladen werden.',
  'signIn.retry': 'Erneut versuchen',
  'session.unavailable.title': 'Die Sitzung lässt sich nicht prüfen',
  'session.unavailable.body': 'Der Server hat nicht geantwortet, daher weiß die Console nicht, ob Sie noch angemeldet sind. Ihre Sitzung kann gültig sein. Versuchen Sie es gleich noch einmal.',
  'session.retry': 'Erneut versuchen',
  'signIn.noMethod': 'Auf diesem Server ist keine Anmeldeart aktiviert.',

  'secondFactor.title': 'Zweiter Faktor',
  'secondFactor.intro': 'Geben Sie den Code Ihrer Authenticator-App ein.',
  'secondFactor.code': 'Code',
  'secondFactor.recoveryIntro': 'Geben Sie einen Ihrer Wiederherstellungscodes ein. Jeder gilt nur einmal.',
  'secondFactor.recoveryCode': 'Wiederherstellungscode',
  'secondFactor.useRecovery': 'Wiederherstellungscode verwenden',
  'secondFactor.useCode': 'Code der App verwenden',
  'secondFactor.submit': 'Weiter',
  'secondFactor.back': 'Von vorn beginnen',

  'error.invalid_credentials': 'Die E-Mail-Adresse oder das Passwort ist falsch.',
  'error.invalid_code': 'Der Code ist nicht gültig.',
  'error.invalid_challenge': 'Die Anmeldung ist abgelaufen. Geben Sie E-Mail-Adresse und Passwort erneut ein.',
  'error.account_locked': 'Das Konto ist gesperrt. Versuchen Sie es in {duration} erneut.',
  'error.cross_origin':
    'Diese Seite wurde unter {origin} geöffnet. Das ist nicht die Adresse, die der Server erwartet. Öffnen Sie die Console unter der Adresse, die der Betreiber als NYKTUS_CONSOLE_URL festgelegt hat.',
  'error.unauthenticated': 'Ihre Sitzung ist beendet. Melden Sie sich erneut an.',
  'error.forbidden': 'Sie dürfen das nicht tun.',
  'error.invalid_request': 'Die Eingabe ist nicht gültig.',
  'error.not_found': 'Das gibt es nicht.',
  'error.rate_limited': 'Zu viele Anfragen. Versuchen Sie es gleich noch einmal.',
  'error.unavailable': 'Der Server ist ausgelastet. Versuchen Sie es gleich noch einmal.',
  'error.server': 'Auf dem Server ist ein Fehler aufgetreten.',
  'error.network': 'Der Server ist nicht erreichbar.',
  'error.sso': 'Die Anmeldung mit SSO ist fehlgeschlagen. Versuchen Sie es erneut oder wenden Sie sich an einen Administrator.',
};
