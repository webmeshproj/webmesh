<template>
  <q-page>
      <div class="full-width">
          <RolesTable />
      </div>
      <div class="full-width">
          <RoleBindingsTable />
      </div>
      <div class="full-width">
          <GroupsTable />
      </div>
  </q-page>
</template>
  
<script lang="ts">
import { defineComponent } from 'vue';

import RolesTable from 'components/tables/RolesTable.vue';
import RoleBindingsTable from 'components/tables/RoleBindingsTable.vue';
import GroupsTable from 'components/tables/GroupsTable.vue';

export default defineComponent({
    name: 'RBACPage',
    components: { RolesTable, RoleBindingsTable, GroupsTable },
    setup () {
        return { };
    }
});
</script>
  