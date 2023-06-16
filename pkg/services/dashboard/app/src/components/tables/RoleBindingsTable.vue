<template>
    <div class="q-pa-md">
        <q-table
            title="Role Bindings"
            :loading="loading"
            :rows="roleBindings"
            :columns="columns"
            :filter="filter"
            :dense="$q.screen.lt.md"
            :grid="$q.screen.xs"
            no-data-label="No role bindings defined in the mesh"
            :no-results-label="`No role bindings found matching filter: ${filter}`"
            row-key="name"
        />
    </div>
</template>
  
<script lang="ts">
import { defineComponent, Ref, ref } from 'vue';

import { Empty } from 'google-protobuf/google/protobuf/empty_pb';
import { RoleBindings, RoleBinding } from '@buf/tinyzimmer_webmesh-api.grpc_web/v1/rbac_pb';
import { useClientStore } from 'stores/client-store';

const columns = [
    { 
        name: 'name', label: 'Name', sortable: true, align: 'left',
        field: (row: RoleBinding) => row.getName()
    },
    { 
        name: 'role', label: 'Role', align: 'left',
        field: (row: RoleBinding) => row.getRole()
    },
];

const clients = useClientStore();

async function listRoleBindings(): Promise<RoleBinding[]> {
    return new Promise((resolve, reject) => {
        clients.adminClient.listRoleBindings(new Empty(), {}, (err: Error, res: RoleBindings) => {
            if (err) {
                reject(err);
                return;
            }
            resolve(res.getItemsList());
        });
    });
}

function useRoleBindingList(): { loading: Ref<boolean>, roleBindings: Ref<RoleBinding[]> } {
    const roleBindings = ref<RoleBinding[]>([]);
    const loading = ref<boolean>(true);
    listRoleBindings().then((r) => {
        roleBindings.value = r;
        loading.value = false;
    });
    return { loading, roleBindings };
}

export default defineComponent({
    name: 'RoleBindingsTable',
    setup () {
        const filter = ref<string>('');
        return { columns, filter, ...useRoleBindingList() };
    }
});
</script>
