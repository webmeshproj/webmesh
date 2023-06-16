<template>
    <div class="q-pa-md">
        <q-table
            title="Role Bindings"
            :rows="roleBindings"
            :columns="columns"
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

function useRoleBindingList(): { roleBindings: Ref<RoleBinding[]> } {
    const roleBindings = ref<RoleBinding[]>([]);
    listRoleBindings().then((r) => {
        roleBindings.value = r;
    });
    return { roleBindings };
}

export default defineComponent({
    name: 'RoleBindingsTable',
    setup () {
        return { columns, ...useRoleBindingList() };
    }
});
</script>
