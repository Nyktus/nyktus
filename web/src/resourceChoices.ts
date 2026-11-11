// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// What the forms of a honeytoken and a honeypot offer to choose from. The specification names the same values.
export const honeytokenTypes = ['web_url', 'web_image', 'dns'] as const;
export const honeypotServices = ['ssh', 'telnet', 'postgres', 'ldap', 'mcp'] as const;
export const severities = ['low', 'medium', 'high', 'critical'] as const;

export type HoneytokenType = (typeof honeytokenTypes)[number];
export type HoneypotService = (typeof honeypotServices)[number];
export type Severity = (typeof severities)[number];
