<template>
  <q-page class="q-pa-md row">
    <div class="column col-6">
      <network-transmission-chart-container class="full-height"/>
    </div>
  </q-page>
</template>

<script lang="ts">
import { defineComponent } from 'vue';
import NetworkTransmissionChartContainer from 'src/components/charts/NetworkTransmissionChartContainer.vue';

export default defineComponent({
    name: 'StatusPage',
    components: { NetworkTransmissionChartContainer },
    setup () {
        return { };
    }
});
</script>
