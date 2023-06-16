<template>
    <q-page>
      <div class="full-width">
        <RolesTable />
      </div>
      <div class="full-width">
        <RoleBindingsTable />
      </div>
    </q-page>
  </template>
  
  <script lang="ts">
  import { defineComponent } from 'vue';
  
  import RolesTable from 'components/tables/RolesTable.vue';
  import RoleBindingsTable from 'components/tables/RoleBindingsTable.vue';

  export default defineComponent({
    name: 'RBACPage',
    components: { RolesTable, RoleBindingsTable },
    setup () {
      return { };
    }
  });
  </script>
  