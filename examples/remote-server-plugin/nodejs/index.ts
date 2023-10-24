import { fastify } from "fastify";
import { fastifyConnectPlugin } from "@connectrpc/connect-fastify";
import { ConnectRouter } from "@connectrpc/connect";
import { Plugin, WatchPlugin } from "@buf/webmeshproj_api.connectrpc_es/v1/plugin_connect";
import { 
    PluginInfo,
    PluginConfiguration,
    Event,
} from "@buf/webmeshproj_api.bufbuild_es/v1/plugin_pb.js";


function routes(router: ConnectRouter) {
    router.service(Plugin, {
        async getInfo(): Promise<PluginInfo> {
            return new PluginInfo({
                name: "Example Typescript Plugin",
                version: "0.0.1",
                description: "Example plugin for Webmesh",
            })
        },

        async configure(config: PluginConfiguration): Promise<void> {
            console.log("configure", config)
        },

        async close(): Promise<void> {
            console.log("node closed")
        }
    })

    router.service(WatchPlugin, {
        async emit(ev: Event): Promise<void> {
            console.log("emit", ev)
        }
    })
}

async function main() {
    const server = fastify();
    await server.register(fastifyConnectPlugin, {
      routes,
    });
    await server.listen({ host: "localhost", port: 8081 });
    console.log("server is listening at", server.addresses());
}

void main();