import { defineStore } from 'pinia';

import {
  RpcError,
  StatusCode,
  GrpcWebClientBaseOptions,
  Metadata,
} from 'grpc-web';
import { NodeClient } from '@buf/tinyzimmer_webmesh-api.grpc_web/v1/node_grpc_web_pb';
import { MeshClient } from '@buf/tinyzimmer_webmesh-api.grpc_web/v1/mesh_grpc_web_pb';
import { AdminClient } from '@buf/tinyzimmer_webmesh-api.grpc_web/v1/admin_grpc_web_pb';
import {
  GetStatusRequest,
  Status,
} from '@buf/tinyzimmer_webmesh-api.grpc_web/v1/node_pb';

const url = '/api';

enum AuthType {
  BASIC = 'basic',
  LDAP = 'ldap',
}

interface AuthUnaryInterceptorOptions {
  type: AuthType;
  username: string;
  password: string;
}

// class AuthUnaryInterceptor<REQ, RESP> implements UnaryInterceptor<REQ, RESP> {
//     options: AuthUnaryInterceptorOptions;

//     constructor(options: AuthUnaryInterceptorOptions) {
//         this.options = options;
//     }

//     intercept(request: Request<REQ, RESP>,
//         invoker: (request: Request<REQ, RESP>) =>
//             Promise<UnaryResponse<REQ, RESP>>): Promise<UnaryResponse<REQ, RESP>> {
//         switch (this.options.type) {
//             case AuthType.BASIC:
//                 request = request.withMetadata('x-webmesh-basic-auth-username', this.options.username);
//                 request = request.withMetadata('x-webmesh-basic-auth-password', this.options.password);
//                 break;
//             case AuthType.LDAP:
//                 break;
//         }
//         return invoker(request);
//     }
// }

export const useClientStore = defineStore('client', {
  state: () => ({
    auth: {} as AuthUnaryInterceptorOptions,
    options: {} as GrpcWebClientBaseOptions,
  }),
  getters: {
    async serverStatus(state): Promise<Status> {
      const client = new NodeClient(url, {}, state.options);
      return new Promise((resolve, reject) => {
        client.getStatus(
          new GetStatusRequest(),
          this.rpcMetadata,
          (err: Error, res: Status) => {
            if (err) reject(err);
            else resolve(res);
          }
        );
      });
    },
    async authenticated(): Promise<boolean> {
      return new Promise((resolve, reject) => {
        this.serverStatus
          .then(() => {
            resolve(true);
          })
          .catch((err: Error) => {
            const rpcErr = err as RpcError;
            if (rpcErr.code === StatusCode.UNAUTHENTICATED) resolve(false);
            else reject(err);
          });
      });
    },
    nodeClient(state): NodeClient {
      return new NodeClient(url, {}, state.options);
    },
    meshClient(state): MeshClient {
      return new MeshClient(url, {}, state.options);
    },
    adminClient(state): AdminClient {
      return new AdminClient(url, {}, state.options);
    },
    rpcMetadata(state): Metadata {
      if (state.auth) {
        switch (state.auth.type) {
          case AuthType.BASIC:
            return {
              'x-webmesh-basic-auth-username': state.auth.username,
              'x-webmesh-basic-auth-password': state.auth.password,
            };
          case AuthType.LDAP:
            return {
              'x-webmesh-ldap-auth-username': state.auth.username,
              'x-webmesh-ldap-auth-password': state.auth.password,
            };
        }
      }
      return {};
    },
  },
  actions: {
    setBasicAuthCredentials(username: string, password: string) {
      const auth = {
        type: AuthType.BASIC,
        username,
        password,
      } as AuthUnaryInterceptorOptions;
      // const interceptor = new AuthUnaryInterceptor(auth);
      this.auth = auth;
      // this.options = {
      //     unaryInterceptors: [interceptor],
      // }
    },
    setLDAPAuthCredentials(username: string, password: string) {
      const auth = {
        type: AuthType.LDAP,
        username,
        password,
      } as AuthUnaryInterceptorOptions;
      // const interceptor = new AuthUnaryInterceptor(auth);
      this.auth = auth;
      // this.options = {
      //     unaryInterceptors: [interceptor],
      // }
    },
  },
});
