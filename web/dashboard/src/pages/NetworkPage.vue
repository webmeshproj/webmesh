<template>
  <q-page class="q-pa-md">
    <div class="row justify-evenly">
      <div class="text-h6">Network Topology</div>
      <div class="column full-width">
        <network-topology />
      </div>
    </div>
  </q-page>
</template>

<script lang="ts">
import { defineComponent } from 'vue';
import NetworkTopology from '../components/graphs/NetworkTopology.vue';

export default defineComponent({
  name: 'NetworkPage',
  components: { NetworkTopology },
  setup() {
    return {};
  },
});
</script>
