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
        >
            <template v-slot:top>
                <TableHeader :refresh="refresh" :filterRef="filter" title="Role Bindings" />
            </template>

            <template v-slot:body="props">
                <q-tr :props="props">
                    <q-td key="name" :props="props" auto-width>
                        {{ props.row.getName() }}
                    </q-td>
                    <q-td key="role" :props="props" auto-width>
                        {{ props.row.getRole() }}
                    </q-td>
                    <q-td key="subjects" :props="props">
                        <q-btn 
                            size="sm" dense 
                            @click="props.row.expand = !props.row.expand"
                            :icon="props.row.expand ? 'remove' : 'add'"
                        >
                            {{ props.row.expand ? 'Collapse Subjects' : 'Expand Subjects' }}
                        </q-btn>
                    </q-td>
                </q-tr>
                <q-tr v-show="props.row.expand">
                    <q-td colspan="100%">
                        <SubjectsTabs :subjects="props.row.getSubjectsList()" />
                    </q-td>
                </q-tr>
            </template>
        </q-table>
    </div>
</template>
  
<script lang="ts">
import { defineComponent, Ref, ref } from 'vue';
import { Empty } from 'google-protobuf/google/protobuf/empty_pb';
import { RoleBindings, RoleBinding } from '@buf/tinyzimmer_webmesh-api.grpc_web/v1/rbac_pb';

import { useClientStore } from 'stores/client-store';
import TableHeader from 'components/tables/TableHeader.vue';
import SubjectsTabs from 'components/tables/SubjectsTabs.vue';

const clients = useClientStore();

const columns = [
    { 
        name: 'name', label: 'Name', sortable: true, align: 'left',
        field: (row: RoleBinding) => row.getName()
    },
    { 
        name: 'role', label: 'Role', align: 'left',
        field: (row: RoleBinding) => row.getRole()
    },
    {
        name: 'subjects', label: 'Subjects', align: 'left',
    }
];

async function listRoleBindings(): Promise<RoleBinding[]> {
    return new Promise((resolve, reject) => {
        clients.adminClient.listRoleBindings(new Empty(), clients.rpcMetadata, (err: Error, res: RoleBindings) => {
            if (err) {
                reject(err);
                return;
            }
            resolve(res.getItemsList());
        });
    });
}

function useRoleBindingList(): {
    loading: Ref<boolean>,
    roleBindings: Ref<RoleBinding[]>,
    refresh: () => void
} {
    const roleBindings = ref<RoleBinding[]>([]);
    const loading = ref<boolean>(true);
    listRoleBindings().then((r) => {
        roleBindings.value = r;
        loading.value = false;
    });
    function refresh() {
        loading.value = true;
        listRoleBindings().then((r) => {
            roleBindings.value = r;
            loading.value = false;
        });
    }
    return { loading, roleBindings, refresh };
}

export default defineComponent({
    name: 'RoleBindingsTable',
    components: { TableHeader, SubjectsTabs },
    setup () {
        const filter = ref<string>('');
        return { columns, filter, ...useRoleBindingList() };
    }
});
</script>
