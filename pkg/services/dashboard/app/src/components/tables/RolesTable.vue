<template>
    <div class="q-pa-md">
        <q-table
            title="Roles"
            :loading="loading"
            :rows="roles"
            :columns="columns"
            :filter="filter"
            :dense="$q.screen.lt.md"
            :grid="$q.screen.xs"
            no-data-label="No roles defined in the mesh"
            :no-results-label="`No roles found matching filter: ${filter}`"
            row-key="name"
        >
            <template v-slot:top>
                <TableHeader :refresh="refresh" :filterRef="filter" title="Roles" />
            </template>

            <template v-slot:body="props">
                <q-tr :props="props">
                    <q-td key="name" :props="props" auto-width>
                        {{ props.row.getName() }}
                    </q-td>
                    <q-td key="rules" :props="props">
                        <q-btn 
                            size="sm" dense 
                            @click="props.row.expand = !props.row.expand"
                            :icon="props.row.expand ? 'remove' : 'add'"
                        >
                            {{ props.row.expand ? 'Collapse Rules' : 'Expand Rules' }}
                        </q-btn>
                    </q-td>
                </q-tr>
            </template>
        </q-table>
    </div>
</template>
  
<script lang="ts">
import { defineComponent, Ref, ref } from 'vue';

import { Empty } from 'google-protobuf/google/protobuf/empty_pb';
import { Roles, Role } from '@buf/tinyzimmer_webmesh-api.grpc_web/v1/rbac_pb';
import { useClientStore } from 'stores/client-store';

import TableHeader from 'components/tables/TableHeader.vue';

const columns = [
    { 
        name: 'name', label: 'Name', sortable: true, align: 'left',
        field: (row: Role) => row.getName()
    },
    { 
        name: 'rules', label: 'Rules', align: 'left',
        field: (row: Role) => row.getRulesList().toString()
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

function useRoleList(): { loading: Ref<boolean>, roles: Ref<Role[]>, refresh: () => void } {
    const roles = ref<Role[]>([]);
    const loading = ref<boolean>(true);
    listRoles().then((r) => {
        roles.value = r;
        loading.value = false;
    });
    function refresh() {
        loading.value = true;
        listRoles().then((r) => {
            roles.value = r;
            loading.value = false;
        });
    }
    return { loading, roles, refresh };
}

export default defineComponent({
    name: 'RolesTable',
    components: { TableHeader },
    setup () {
        const filter = ref<string>('');
        return { columns, filter, ...useRoleList() };
    }
});
</script>
