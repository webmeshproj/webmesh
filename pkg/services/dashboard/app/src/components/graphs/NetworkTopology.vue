<template>
    <div id="network" style="height:600px">
        <q-inner-loading :showing="loading">
            <q-spinner-grid size="xl" color="primary" />
        </q-inner-loading>
    </div>
    <q-popup-proxy v-model="showDetails">
        <q-card v-if="nodeDetails">
            <q-card-section>
                <div class="text-h6">{{ nodeDetails.getId() }}</div>
            </q-card-section>

            <q-card-section class="q-pa-md row">
                <div class="column col-6">
                    <div class="text-subtitle1">Networking</div>
                    <CopyableField title="Public Endpoint" :value="nodeDetails.getPrimaryEndpoint()" />
                    <CopyableField title="Mesh IPv4 Address" :value="nodeDetails.getPrivateIpv4()" />
                    <CopyableField title="Mesh IPv6 Address" :value="nodeDetails.getPrivateIpv6()" />
                    <CopyableField title="Zone Awareness ID" :value="nodeDetails.getZoneAwarenessId()" />
                </div>
                <div class="column col-6">
                    <div class="text-subtitle1">Mesh</div>
                    <div>
                        <strong>Cluster Status:</strong>
                        <ClusterStatus :status="nodeDetails.getClusterStatus()" />
                    </div>
                    <CopyableField title="Public Key" :value="nodeDetails.getPublicKey()" />
                </div>
            </q-card-section>
        </q-card>
    </q-popup-proxy>
</template>
  
<script lang="ts">
import { defineComponent, ref } from 'vue';
import { parseDOTNetwork, Network, Data, Options } from 'vis-network';
import { Empty } from 'google-protobuf/google/protobuf/empty_pb';
import { GetNodeRequest, MeshNode, MeshGraph } from '@buf/tinyzimmer_webmesh-api.grpc_web/v1/mesh_pb';

import { useClientStore } from 'stores/client-store';
import ClusterStatus from 'components/ClusterStatus.vue';
import CopyableField from 'components/CopyableField.vue';

export default defineComponent({
    name: 'NetworkTopology',
    components: { ClusterStatus, CopyableField },
    mounted () {
        this.buildNetworkGraph();
    },
    computed: {
        showDetails(): boolean { return this.detailsHovering || this.detailsSelected; }
    },
    setup () {
        const clients = useClientStore();
        const loading = ref<boolean>(true);
        const detailsHovering = ref<boolean>(false);
        const detailsSelected = ref<boolean>(false);
        const nodeDetails = ref<MeshNode>();

        function getNodeDetails(id: string): Promise<MeshNode> {
            return new Promise((resolve, reject) => {
                const req = new GetNodeRequest();
                req.setId(id)
                clients.meshClient.getNode(req, {}, (err: Error, res: MeshNode) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(res);
                    }
                });
            });
        }

        function getNetworkGraph(): Promise<{data: Data, options: Options}> {
            loading.value = true;
            return new Promise((resolve, reject) => {
                clients.meshClient.getMeshGraph(new Empty(), {}, (err: Error, res: MeshGraph) => {
                    if (err) {
                        reject(err);
                    } else {
                        const parsed = parseDOTNetwork(res.getDot());
                        const data: Data = { nodes: parsed.nodes, edges: parsed.edges };
                        const options: Options = parsed.options;
                        options.interaction =  { hover: true };
                        loading.value = false;
                        resolve({data, options});
                    }
                });
            });
        };

        async function buildNetworkGraph(): Promise<void> {
            const data = await getNetworkGraph();
            const elem = document.getElementById('network');
            if (elem) {
                const network = new Network(elem, data.data, data.options);
                network.on('hoverNode', (ev: { node: string }) => {
                    if (detailsSelected.value) return;
                    getNodeDetails(ev.node).then((node) => {
                        nodeDetails.value = node;
                        detailsHovering.value = true;
                    });
                });
                network.on('blurNode', () => {
                    detailsHovering.value = false;
                });
                network.on('selectNode', (ev: { nodes: string[] }) => {
                    if (ev.nodes.length == 0) return;
                    getNodeDetails(ev.nodes[ev.nodes.length - 1]).then((node) => {
                        nodeDetails.value = node;
                        detailsSelected.value = true;
                    });
                });
                network.on('deselectNode', () => {
                    detailsSelected.value = false;
                });
            }
        }

        return { 
            buildNetworkGraph,
            detailsHovering,
            detailsSelected,
            loading,
            nodeDetails
        };
    }
});
</script>
