<template>
    <strong>Public Key:</strong> {{ publicKey }}
    <q-btn size="xs" dense flat @click="() => {
        copyToClipboard(publicKey);
    }">
        <q-icon name="content_copy" />
        <q-tooltip anchor="top right" self="top start">
            Copy to clipboard
        </q-tooltip>
    </q-btn>
</template>

<script lang="ts">
import { defineComponent } from 'vue';

async function copyToClipboard(val: string): Promise<void> {
    return await navigator?.clipboard.writeText(val);
}

export default defineComponent({
    name: 'PublicKey',
    props: {
        publicKey: {
            type: String,
            required: true
        },
    },
    setup() {
        return { copyToClipboard };
    }
});
</script>
      