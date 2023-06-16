<template>
    <div class="q-pa-md">
        <q-table
            title="Mesh Nodes"
            :rows="nodes"
            :columns="columns"
            row-key="name"
        />
    </div>
</template>
  
<script lang="ts">
import { defineComponent, Ref, ref } from 'vue';

import { Empty } from 'google-protobuf/google/protobuf/empty_pb';
import { NodeList, MeshNode } from '@buf/tinyzimmer_webmesh-api.grpc_web/v1/mesh_pb';
import { useClientStore } from 'stores/client-store';

const columns = [
    { 
        name: 'id', label: 'ID', sortable: true, align: 'left',
        field: (row: MeshNode) => row.getId()
    },
    { 
        name: 'status', label: 'Status', align: 'left',
        field: (row: MeshNode) => row.getClusterStatus()
    },
    { 
        name: 'endpoint', label: 'Primary Endpoint', align: 'left',
        field: (row: MeshNode) => row.getPrimaryEndpoint()
    },
    {
        name: 'ip4', label: 'Mesh IPv4', align: 'left',
        field: (row: MeshNode) => row.getPrivateIpv4()
    },
    { 
        name: 'ip6', label: 'Mesh IPv6', align: 'left',
        field: (row: MeshNode) => row.getPrivateIpv6()
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

function useNodeList(): { nodes: Ref<MeshNode[]> } {
    const nodes = ref<MeshNode[]>([]);
    listNodes().then((n) => {
        nodes.value = n;
    });
    return { nodes };
}

export default defineComponent({
    name: 'NodesTable',
    setup () {
        return { columns, ...useNodeList() };
    }
});
</script>
  