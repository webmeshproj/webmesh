import { defineStore } from 'pinia';

import { NodeClient } from '@buf/tinyzimmer_webmesh-api.grpc_web/v1/node_grpc_web_pb';
import { MeshClient } from '@buf/tinyzimmer_webmesh-api.grpc_web/v1/mesh_grpc_web_pb';
import { AdminClient } from '@buf/tinyzimmer_webmesh-api.grpc_web/v1/admin_grpc_web_pb';
import { GetStatusRequest, Status } from '@buf/tinyzimmer_webmesh-api.grpc_web/v1/node_pb';

const url = '/api'

export const useClientStore = defineStore('client', {
  state: () => ({
    metadata: {},
  }),
  getters: {
    async serverStatus(state): Promise<Status> {
      return new Promise((resolve, reject) => {
        this.nodeClient.getStatus(new GetStatusRequest(), state.metadata, (err: Error, res: Status) => {
          if (err) reject(err);
          else resolve(res);
        })
      });
    },
    nodeClient(state): NodeClient {
      return new NodeClient(url, state.metadata)
    },
    meshClient(state): MeshClient {
      return new MeshClient(url, state.metadata)
    },
    adminClient(state): AdminClient {
      return new AdminClient(url, state.metadata)
    }
  },
  actions: {
    setMetadata(meta: object) {
      this.metadata = meta;
    },
  },
});
