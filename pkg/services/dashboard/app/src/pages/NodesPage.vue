<template>
    <q-page class="row items-center justify-evenly">
      <NodesTable />
    </q-page>
  </template>
  
  <script lang="ts">
  import { defineComponent } from 'vue';
  import NodesTable from 'components/tables/NodesTable.vue';

  export default defineComponent({
    name: 'NodesPage',
    components: { NodesTable },
    setup () {
      return { };
    }
  });
  </script>
  