<!--
SPDX-FileCopyrightText: The Nyktus Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { useId, useTemplateRef, watch } from 'vue';
import { t } from '../i18n';

const props = defineProps<{ open: boolean; title: string; confirm: string; busy?: boolean }>();
const emit = defineEmits<{ confirm: []; cancel: [] }>();

const dialog = useTemplateRef<HTMLDialogElement>('dialog');
// A page can hold several dialogs, so each names its title by an id of its own.
const titleId = useId();

// A request that is on its way cannot be called back, so the dialog stays until it is answered:
// closing it would look like an abort, and the change would happen all the same.
function cancel(): void {
  if (!props.busy) {
    emit('cancel');
  }
}

watch(
  () => props.open,
  (open) => {
    const element = dialog.value;
    if (element === null) {
      return;
    }
    if (open && !element.open) {
      // The modal dialog of the browser traps the focus and closes with Escape.
      if (typeof element.showModal === 'function') {
        element.showModal();
      } else {
        element.setAttribute('open', '');
      }
    } else if (!open && element.open) {
      element.close();
    }
  },
  { flush: 'post' },
);
</script>

<template>
  <dialog ref="dialog" class="dialog panel" :aria-labelledby="titleId" @cancel.prevent="cancel">
    <h2 :id="titleId">{{ title }}</h2>
    <div class="body"><slot /></div>
    <div class="actions">
      <button class="button button-ghost" type="button" :disabled="busy" @click="cancel">{{ t('common.cancel') }}</button>
      <button class="button danger" type="button" :disabled="busy" @click="emit('confirm')">{{ confirm }}</button>
    </div>
  </dialog>
</template>

<style scoped>
.dialog {
  width: min(92vw, 30rem);
  padding: 1.5rem;
  color: var(--ink);
}

.dialog::backdrop {
  background: rgb(19 32 26 / 0.45);
}

.body {
  margin: 0.75rem 0 1.25rem;
}

.actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.75rem;
}

.danger {
  background: var(--danger);
  color: #ffffff;
}
</style>
