// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

/** The bounds of a password, counted in code points after normalization, as the server counts them. */
export const passwordLength = { min: 12, max: 128 } as const;

export type PasswordProblem = 'too_short' | 'too_long' | 'mismatch';

/**
 * Checks a new password before it is sent, so that the user does not wait for the
 * server to tell them that it is too short or mistyped. The server decides; this
 * is for usability only.
 */
export function checkNewPassword(password: string, repetition: string): PasswordProblem | undefined {
  const length = [...password.normalize('NFC')].length;
  if (length < passwordLength.min) {
    return 'too_short';
  }
  if (length > passwordLength.max) {
    return 'too_long';
  }
  return password === repetition ? undefined : 'mismatch';
}
