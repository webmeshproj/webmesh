<template>
  <q-dialog persistent ref="dialogRef" @hide="onDialogHide">
    <q-card class="bg-teal text-white" style="width: 50%">
      <q-card-section>
        <div class="text-h6">Login to Continue</div>
      </q-card-section>

      <q-card-section class="q-pt-none">
        The server has authentication enabled. Please enter your credentials to
        continue.
      </q-card-section>

      <q-card-actions class="bg-white text-teal q-pa-sm">
        <q-form @submit="onOKClick" class="column full-width">
          <div>
            <div class="q-pa-sm">
              <q-input outlined dense v-model="username" label="Username" />
            </div>
            <div class="q-pa-sm">
              <q-input
                outlined
                dense
                v-model="password"
                label="Password"
                type="password"
              />
            </div>
            <div align="right">
              <q-btn flat label="Login" @click="onOKClick" type="submit" />
            </div>
          </div>
        </q-form>
      </q-card-actions>
    </q-card>
  </q-dialog>
</template>

<script lang="ts">
import { defineComponent, ref } from 'vue';
import { useQuasar, useDialogPluginComponent } from 'quasar';
import { useClientStore } from 'stores/client-store';

export default defineComponent({
  name: 'AuthDialog',
  emits: [...useDialogPluginComponent.emits],
  setup() {
    const { dialogRef, onDialogHide, onDialogOK, onDialogCancel } =
      useDialogPluginComponent();
    const username = ref<string>('');
    const password = ref<string>('');
    const $q = useQuasar();
    const clients = useClientStore();
    return {
      dialogRef,
      username,
      password,
      onDialogHide,
      onOKClick() {
        clients.setBasicAuthCredentials(username.value, password.value);
        clients.authenticated.then((authenticated: boolean) => {
          if (authenticated) {
            onDialogOK();
            return;
          }
          $q.notify({
            message: 'Invalid Credentials',
            type: 'negative',
            position: 'top',
            timeout: 1000,
          });
        });
      },
      onCancelClick: onDialogCancel,
    };
  },
});
</script>
