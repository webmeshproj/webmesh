<template>
    <div v-if="loading"><q-skeleton height="600px" /></div>
    <div v-if="!loading" id="network" style="height:600px"></div>
</template>
  
<script lang="ts">
import { defineComponent, ref } from 'vue';
import { parseDOTNetwork, Network, Data, Options } from 'vis-network';
import { Empty } from 'google-protobuf/google/protobuf/empty_pb';
import { GetNodeRequest, MeshNode, MeshGraph } from '@buf/tinyzimmer_webmesh-api.grpc_web/v1/mesh_pb';

import { useClientStore } from 'stores/client-store';

const clients = useClientStore();



export default defineComponent({
    name: 'NetworkTopology',
    mounted () {
        this.buildNetworkGraph();
    },
    setup () {
        const loading = ref<boolean>(true);
        
        async function getNodeDetails(id: string): Promise<MeshNode> {
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

        async function getNetworkGraph(): Promise<{data: Data, options: Options}> {
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
                    console.log(ev.node);
                    getNodeDetails(ev.node).then((node) => {
                        console.log(node.toObject());
                    });
                })
            }
        }

        return { buildNetworkGraph, loading };
    }
});
</script>
