<template>
  <div>
    <strong>{{ title }}:</strong> {{ value || 'N/A' }}
    <q-btn
      v-if="value"
      icon="content_copy"
      size="xs"
      dense
      flat
      @click="copyToClipboard"
    >
      <q-tooltip anchor="top right" self="top start">{{
        tooltipText
      }}</q-tooltip>
    </q-btn>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref } from 'vue';

export default defineComponent({
  name: 'CopyableField',
  props: {
    title: {
      type: String,
      required: true,
    },
    value: {
      type: String,
      required: true,
    },
  },
  setup(props) {
    const tooltipText = ref<string>('Copy to clipboard');
    async function copyToClipboard(): Promise<void> {
      navigator?.clipboard.writeText(props.value).then(() => {
        tooltipText.value = 'Copied!';
        setTimeout(() => {
          tooltipText.value = 'Copy to clipboard';
        }, 2000);
      });
    }
    return { copyToClipboard, tooltipText };
  },
});
</script>
