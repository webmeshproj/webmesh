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
                <q-tr v-show="props.row.expand">
                    <q-td></q-td>
                    <q-td>
                        <q-list style="max-width: 50%">
                            <q-item dense :key="idx" v-for="(rule, idx) in props.row.getRulesList()">
                                <q-item-section>
                                    <q-item-label>Resources</q-item-label>
                                    <q-list>
                                        <q-item dense v-for="(resource, idx) in resourceStrings(rule.getResourcesList())" :key="idx">
                                            <q-item-label caption>{{ resource }}</q-item-label>
                                        </q-item>
                                    </q-list>
                                </q-item-section>
                                <q-item-section>
                                    <q-item-label>Actions</q-item-label>
                                    <q-list>
                                        <q-item dense v-for="(verb, idx) in verbStrings(rule.getVerbsList())" :key="idx">
                                            <q-item-label caption>{{ verb }}</q-item-label>
                                        </q-item>
                                    </q-list>
                                </q-item-section>
                            </q-item>
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
import { Roles, Role, RuleResource, RuleVerbs } from '@buf/tinyzimmer_webmesh-api.grpc_web/v1/rbac_pb';
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

function useRoleList(): {
    loading: Ref<boolean>,
    roles: Ref<Role[]>,
    refresh: () => void
} {
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

function resourceStrings(resources: RuleResource[]): string[] {
    const out: string[] = [];
    let hasAll = false;
    resources.forEach((r) => {
        switch (r) {
            case RuleResource.RESOURCE_ALL:
                out.push('All');
                hasAll = true;
                break;
            case RuleResource.RESOURCE_VOTES:
                out.push('Votes');
                break;
            case RuleResource.RESOURCE_ROLES:
                out.push('Roles');
                break;
            case RuleResource.RESOURCE_ROLE_BINDINGS:
                out.push('Role Bindings');
                break;
            case RuleResource.RESOURCE_GROUPS:
                out.push('Groups');
                break;
            case RuleResource.RESOURCE_NETWORK_ACLS:
                out.push('Network ACLs');
                break;
            case RuleResource.RESOURCE_ROUTES:
                out.push('Routes');
                break;
            case RuleResource.RESOURCE_DATA_CHANNELS:
                out.push('Data Channels');
                break;
            default:
                out.push('Unknown');
                break;
        }
    });
    if (hasAll) {
        return ['All'];
    }
    return out;
}

function verbStrings(verbs: RuleVerbs[]): string[] {
    const out: string[] = [];
    let hasAll = false;
    verbs.forEach((v) => {
        switch (v) {
            case RuleVerbs.VERB_ALL:
                out.push('All');
                hasAll = true;
                break;
            case RuleVerbs.VERB_PUT:
                out.push('Put');
                break;
            case RuleVerbs.VERB_GET:
                out.push('Get');
                break;
            case RuleVerbs.VERB_DELETE:
                out.push('Delete');
                break;
            default:
                out.push('Unknown');
                break;
        }
    });
    if (hasAll) {
        return ['All'];
    }
    return out;
}

export default defineComponent({
    name: 'RolesTable',
    components: { TableHeader },
    setup () {
        const filter = ref<string>('');
        return { columns, filter, resourceStrings, verbStrings, ...useRoleList() };
    }
});
</script>
