// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { api, setUnauthenticatedHandler } from '../api/client';
import { createSessionStore } from './store';

export const session = createSessionStore(api);

setUnauthenticatedHandler(() => {
  session.expire();
});
