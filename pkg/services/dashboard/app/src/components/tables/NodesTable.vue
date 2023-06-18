<template>
    <div class="q-pa-md">
        <q-table
            title="Mesh Nodes"
            :loading="loading"
            :rows="nodes"
            :columns="columns"
            :filter="filter"
            :dense="$q.screen.lt.md"
            :grid="$q.screen.xs"
            no-data-label="No nodes connected to the mesh"
            :no-results-label="`No nodes found matching filter: ${filter}`"
            row-key="id"
            class="sticky-header-column-table"
        >
            <template v-slot:top>
                <TableHeader :refresh="refresh" :filterRef="filter" title="Mesh Nodes" />
            </template>

            <!-- Cluster Status Cell -->
            <template v-slot:body-cell-status="props">
                <q-td :props="props">
                    <ClusterStatus :status="props.value" />
                </q-td>
            </template>
=
            <!-- Table Body -->
            <template v-slot:body="props">
                <q-tr :props="props">
                    <q-td key="expand" :props="props" auto-width>
                        <q-btn
                            round
                            dense
                            size="sm"
                            color="primary"
                            @click="props.row.expand = !props.row.expand"
                            :icon="props.row.expand ? 'remove' : 'add'"
                        />
                    </q-td>
                    <q-td key="id" :props="props" auto-width>
                        {{ props.row.getId() }}
                    </q-td>
                    <q-td key="status" :props="props">
                        <ClusterStatus :status="props.row.getClusterStatus()" />
                    </q-td>
                    <q-td key="endpoint" :props="props">
                        {{  props.row.getPrimaryEndpoint() || 'N/A' }}
                    </q-td>
                    <q-td key="ip4" :props="props">
                        {{ props.row.getPrivateIpv4()?.split('/')[0] || 'N/A' }}
                    </q-td>
                    <q-td key="ip6" :props="props">
                        {{ props.row.getPrivateIpv6() || 'N/A' }}
                    </q-td>
                    <q-td key="createdAt" :props="props">
                        {{ formatTimestamp(props.row.getCreatedAt()) }}
                    </q-td>
                    <q-td key="updatedAt" :props="props">
                        {{ formatTimestamp(props.row.getUpdatedAt()) }}
                    </q-td>
                </q-tr>
                <q-tr v-show="props.row.expand">
                    <q-td></q-td>
                    <q-td colspan="100%">
                        <div class="row">
                            <div class="text-caption col-12">
                                <PublicKey :publicKey="props.row.getPublicKey() || 'N/A'" />
                            </div>
                            <div class="text-caption col-12">
                                <strong>WireGuard Endpoints:</strong> {{  props.row.getWireguardEndpointsList().join(',') || 'N/A' }}
                            </div>
                            <div class="text-caption" v-if="props.row.getZoneAwarenessId()">
                                <strong>Zone Awareness ID:</strong> <i>{{ props.row.getZoneAwarenessId() }}</i>
                            </div>
                        </div>
                    </q-td>
                </q-tr>
            </template>

            <!-- No data message -->
            <template v-slot:no-data="{ message }">
                <div class="full-width row flex-center text-info q-gutter-sm">
                    <q-icon size="sm" name="sentiment_dissatisfied" />
                    <span>{{ message }}</span>
                </div>
            </template>
        </q-table>
    </div>
</template>
  
<script lang="ts">
import { defineComponent, Ref, ref } from 'vue';

import { Empty } from 'google-protobuf/google/protobuf/empty_pb';
import { Timestamp } from 'google-protobuf/google/protobuf/timestamp_pb';
import { NodeList, MeshNode } from '@buf/tinyzimmer_webmesh-api.grpc_web/v1/mesh_pb';

import { useClientStore } from 'stores/client-store';
import TableHeader from 'components/tables/TableHeader.vue';
import ClusterStatus from 'components/ClusterStatus.vue';
import PublicKey from 'components/PublicKey.vue';

function formatTimestamp(val: Timestamp): string {
    return val.toDate().toLocaleString();
}

const columns = [
    {
        name: 'expand', label: '', field: 'expand', align: 'center', sortable: false,
    },
    {
        name: 'id', required: true, label: 'ID', sortable: true, align: 'left',
        field: (row: MeshNode) => row.getId()
    },
    { 
        name: 'status', label: 'Status', align: 'left',
    },
    { 
        name: 'endpoint', label: 'Primary Endpoint', align: 'left',
    },
    {
        name: 'ip4', label: 'Mesh IPv4', align: 'left',
    },
    { 
        name: 'ip6', label: 'Mesh IPv6', align: 'left',
    },
    {
        name: 'createdAt', label: 'Joined', align: 'left',
    },
    {
        name: 'updatedAt', label: 'Last Update', align: 'left',
    },
];

const clients = useClientStore();

async function listNodes(): Promise<MeshNode[]> {
    return new Promise((resolve, reject) => {
        clients.meshClient.listNodes(new Empty(), {}, (err: Error, res: NodeList) => {
            if (err) {
                reject(err);
                return;
            }
            resolve(res.getNodesList());
        });
    });
}

function useNodeList(): { 
    loading: Ref<boolean>, 
    nodes: Ref<MeshNode[]>, 
    refresh: () => void 
} {
    const nodes = ref<MeshNode[]>([]);
    const loading = ref<boolean>(true);
    listNodes().then((n) => {
        nodes.value = n;
        loading.value = false;
    });
    function refresh() {
        loading.value = true;
        listNodes().then((n) => {
            nodes.value = n;
            loading.value = false;
        });
    };
    return { loading, nodes, refresh };
}

export default defineComponent({
    name: 'NodesTable',
    components: { TableHeader, ClusterStatus, PublicKey },
    setup () {
        const filter = ref<string>('');
        return { formatTimestamp, columns, filter, ...useNodeList() };
    }
});
</script>
