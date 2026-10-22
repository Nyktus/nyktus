// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createApp } from 'vue';
import App from './App.vue';
import { locale } from './i18n';
import { createConsoleRouter } from './router';
import { session } from './session';
import './styles/fonts.css';
import './styles/tokens.css';
import './styles/base.css';

document.documentElement.lang = locale.value;

const router = createConsoleRouter(session);
createApp(App).use(router).mount('#app');
