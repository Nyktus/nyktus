<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { t } from '../i18n';
import { passwordLength } from '../session/passwordRules';

const password = defineModel<string>('password', { required: true });
const repeat = defineModel<string>('repeat', { required: true });
</script>

<template>
  <div class="field">
    <label for="new-password">{{ t('password.new') }}</label>
    <input
      id="new-password"
      v-model="password"
      type="password"
      name="new-password"
      autocomplete="new-password"
      aria-describedby="password-hint"
      required
    />
    <span id="password-hint" class="hint">{{ t('password.hint', passwordLength) }}</span>
  </div>
  <div class="field">
    <label for="repeat-password">{{ t('password.repeat') }}</label>
    <input
      id="repeat-password"
      v-model="repeat"
      type="password"
      name="repeat-password"
      autocomplete="new-password"
      required
    />
  </div>
</template>
