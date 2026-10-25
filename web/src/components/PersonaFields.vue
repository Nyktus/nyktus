<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { t } from '../i18n';
import type { PersonaField } from '../personaRules';

// The values of a persona that a deception or an artifact needs, for applying one and for
// adding one. A key that the scenario has already shows its value and cannot be changed:
// files that were made with it must go on agreeing with the ones that follow. The check in
// the browser is a convenience, the server decides.
defineProps<{
  fields: readonly PersonaField[];
  /** The persona of the scenario, which a new deception or artifact joins. */
  fixed?: Readonly<Record<string, string>>;
  /** The text for a field whose value is not valid, by key. */
  problems: Readonly<Record<string, string>>;
  legend: string;
  hint: string;
}>();

const values = defineModel<Record<string, string>>({ required: true });

function has(fixed: Readonly<Record<string, string>> | undefined, key: string): boolean {
  return fixed !== undefined && Object.hasOwn(fixed, key);
}

function set(key: string, event: Event): void {
  values.value = { ...values.value, [key]: (event.target as HTMLInputElement).value };
}
</script>

<template>
  <fieldset v-if="fields.length > 0" class="persona">
    <legend>{{ legend }}</legend>
    <p class="hint">{{ hint }}</p>
    <div v-for="field in fields" :key="field.key" class="field">
      <label :for="`persona-${field.key}`">{{ field.label }}</label>
      <input
        v-if="has(fixed, field.key)"
        :id="`persona-${field.key}`"
        :value="fixed?.[field.key]"
        type="text"
        readonly
        dir="auto"
        :aria-describedby="`persona-${field.key}-hint`"
      />
      <input
        v-else
        :id="`persona-${field.key}`"
        :value="values[field.key] ?? ''"
        type="text"
        autocomplete="off"
        spellcheck="false"
        :placeholder="field.example"
        :aria-describedby="`persona-${field.key}-hint`"
        :aria-invalid="problems[field.key] !== undefined"
        :maxlength="field.kind === 'text' ? 200 : 253"
        @input="set(field.key, $event)"
      />
      <span :id="`persona-${field.key}-hint`" class="hint">
        <template v-if="has(fixed, field.key)">{{ t('persona.fixed') }}</template>
        <template v-else>{{ t(`persona.${field.kind}`) }} {{ t('persona.example', { example: field.example }) }}</template>
      </span>
      <span v-if="problems[field.key]" class="hint problem" role="alert">{{ problems[field.key] }}</span>
    </div>
  </fieldset>
</template>

<style scoped>
.hint {
  color: var(--slate);
  font-size: 0.8125rem;
}

.problem {
  color: var(--danger);
}

.persona {
  display: grid;
  gap: 0.9rem;
  margin: 0;
  padding: 0.9rem;
  border: 1px solid var(--line);
  border-radius: var(--radius-sm);
}

.persona legend {
  padding: 0 0.3rem;
  font-weight: 600;
}
</style>
