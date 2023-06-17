<template>
    <div class="q-pa-md">
        <q-table
            title="Role Bindings"
            :loading="loading"
            :rows="groups"
            :columns="columns"
            :filter="filter"
            :dense="$q.screen.lt.md"
            :grid="$q.screen.xs"
            no-data-label="No role bindings defined in the mesh"
            :no-results-label="`No role bindings found matching filter: ${filter}`"
            row-key="name"
        >
            <template v-slot:top>
                <TableHeader :refresh="refresh" :filterRef="filter" title="Groups" />
            </template>

            <template v-slot:body="props">
                <q-tr :props="props">
                    <q-td key="name" :props="props" auto-width>
                        {{ props.row.getName() }}
                    </q-td>
                    <q-td key="nodes" :props="props">
                        <q-list padding class="rounded-borders">
                            <q-expansion-item
                                dense
                                dense-toggle
                                expand-separator
                                icon="computer"
                                label="Expand"
                                header-class="bg-secondary text-white"
                            >
                                <q-list>
                                    <q-item dense v-for="node in nodesInGroup(props.row)" :key="node">
                                        <q-item-section>
                                            <q-item-label caption>{{ node }}</q-item-label>
                                        </q-item-section>
                                    </q-item>
                                    <q-item v-if="nodesInGroup(props.row).length == 0">
                                        <q-item-section>
                                            <q-item-label caption>None</q-item-label>
                                        </q-item-section>
                                    </q-item>
                                </q-list>
                            </q-expansion-item>
                        </q-list>
                    </q-td>
                    <q-td key="users" :props="props">
                        <q-list padding class="rounded-borders">
                            <q-expansion-item
                                dense
                                dense-toggle
                                expand-separator
                                icon="person"
                                label="Expand"
                                header-class="bg-secondary text-white"
                            >
                                <q-list>
                                    <q-item dense v-for="user in usersInGroup(props.row)" :key="user">
                                        <q-item-section>
                                            <q-item-label caption>{{ user }}</q-item-label>
                                        </q-item-section>
                                    </q-item>
                                    <q-item v-if="usersInGroup(props.row).length == 0">
                                        <q-item-section>
                                            <q-item-label caption>None</q-item-label>
                                        </q-item-section>
                                    </q-item>
                                </q-list>
                            </q-expansion-item>
                        </q-list>
                    </q-td>
                </q-tr>
            </template>
        </q-table>
    </div>
</template>

<script lang="ts">
import { defineComponent, Ref, ref } from 'vue';
import { Empty } from 'google-protobuf/google/protobuf/empty_pb';
import { Groups, Group, SubjectType } from '@buf/tinyzimmer_webmesh-api.grpc_web/v1/rbac_pb';

import { useClientStore } from 'stores/client-store';
import TableHeader from 'components/tables/TableHeader.vue';

const clients = useClientStore();

const columns = [
    { 
        name: 'name', label: 'Name', sortable: true, align: 'left',
        field: (row: Group) => row.getName()
    },
    { 
        name: 'nodes', label: 'Nodes', align: 'left',
    },
    {
        name: 'users', label: 'Users', align: 'left',
    }
];

async function listGroups(): Promise<Group[]> {
    return new Promise((resolve, reject) => {
        clients.adminClient.listGroups(new Empty(), {}, (err: Error, res: Groups) => {
            if (err) {
                reject(err);
                return;
            }
            resolve(res.getItemsList());
        });
    });
}

function useGroupList(): {
    loading: Ref<boolean>,
    groups: Ref<Group[]>,
    refresh: () => void
} {
    const groups = ref<Group[]>([]);
    const loading = ref<boolean>(true);
    listGroups().then((r) => {
        groups.value = r;
        loading.value = false;
    });
    function refresh() {
        loading.value = true;
        listGroups().then((r) => {
            groups.value = r;
            loading.value = false;
        });
    }
    return { loading, groups, refresh };
}

function usersInGroup(group: Group): string[] {
    const out: string[] = [];
    group.getSubjectsList().forEach((s) => {
        if (s.getType() == SubjectType.SUBJECT_USER || s.getType() == SubjectType.SUBJECT_ALL) {
            out.push(s.getName());
        }
    })
    return out;
}

function nodesInGroup(group: Group): string[] {
    const out: string[] = [];
    group.getSubjectsList().forEach((s) => {
        if (s.getType() == SubjectType.SUBJECT_NODE || s.getType() == SubjectType.SUBJECT_ALL) {
            out.push(s.getName());
        }
    })
    return out;
}

export default defineComponent({
    name: 'RoleBindingsTable',
    components: { TableHeader },
    setup () {
        const filter = ref<string>('');
        return { columns, filter, usersInGroup, nodesInGroup, ...useGroupList() };
    }
});
</script>