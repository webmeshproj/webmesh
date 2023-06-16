<template>
    <div class="q-pa-md">
        <q-table
            title="Roles"
            :rows="roles"
            :columns="columns"
            row-key="name"
        />
    </div>
</template>
  
<script lang="ts">
import { defineComponent, Ref, ref } from 'vue';

import { Empty } from 'google-protobuf/google/protobuf/empty_pb';
import { Roles, Role } from '@buf/tinyzimmer_webmesh-api.grpc_web/v1/rbac_pb';
import { useClientStore } from 'stores/client-store';

const columns = [
    { 
        name: 'name', label: 'Name', sortable: true, align: 'left',
        field: (row: Role) => row.getName()
    },
    { 
        name: 'rules', label: 'Rules', align: 'left',
        field: (row: Role) => row.getRulesList()
    },
];

const clients = useClientStore();

async function listRoles(): Promise<Role[]> {
    return new Promise((resolve, reject) => {
        clients.adminClient.listRoles(new Empty(), {}, (err: Error, res: Roles) => {
            if (err) {
                reject(err);
                return;
            }
            resolve(res.getItemsList());
        });
    });
}

function useRoleList(): { roles: Ref<Role[]> } {
    const roles = ref<Role[]>([]);
    listRoles().then((r) => {
        roles.value = r;
    });
    return { roles };
}

export default defineComponent({
    name: 'RolesTable',
    setup () {
        return { columns, ...useRoleList() };
    }
});
</script>
