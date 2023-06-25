# What is Webmesh?

Webmesh is a project that aims to provide a simple, secure, and scalable way to connect devices and services across the internet.

It is inspired by several other projects that have emerged over the years such as TailScale, ZeroTier, and OpenZiti.
The core difference, however, is that every node in the network is also, optionally, a controller server.
Another core aim is to offload as much networking onto pre-existing protocols as possible and strive to maintain a simple codebase.
This is one of the reasons the project is built on top of [WireGuard](https://www.wireguard.com/) and doesn't attempt to implement another Virtual Network Layer.

Nodes connected to the network take on one of three roles. They can be a client, a server, or both.
A client is a node that is connected to the network but does not provide any services, except to itself.
A server is a node that is connected to the network and provides services to other nodes.
When a server node is also the leader, it is referred to as a controller.
Other server nodes will proxy requests to mutate the network to the controller.
State is maintained on every connected node via Raft consensus.
This allows for the network to be highly available and fault tolerant.

The network supports role-based access control and can be configured to allow or deny access to specific services and operations to specific nodes.
The same goes for network access controls.
This is the recommended way to run the network, but insecure options are provided for testing and development purposes.
The current supported authentication methods are:

- mTLS
- LDAP
- Basic Auth

Examples of different topologies and usages can be found in the [examples](examples/) directory.
More examples and documentation will be added as the project matures.

**This project is not yet ready for production use, but I hope to rapidly get there**

# Webmesh Node

This repository contains the core functionality of the Webmesh Project.
It implements the [API](https://github.com/webmeshproj/api) in Go.

## Getting Started

If you'd like to play with the project on Kubernetes, there is a work-in-progress Operator in the [operator](https://github.com/webmeshproj/operator/) repository.
It works fine on most clusters, including ephemeral docker-based ones, but is not yet ready for production use.

More detailed instructions will be added as the project matures, but to test starting a single node anew, you can run the following:

```bash
# You can remove the --global.no-ipv6 flag if you have IPv6 connectivity on your docker network.
docker run --rm --privileged --name=bootstrap-node ghcr.io/webmeshproj/node:latest \
    --global.insecure \
    --global.no-ipv6 \
    --global.detect-endpoints \
    --global.detect-private-endpoints \
    --bootstrap.enabled
```

Once the node is ready, to join another node to the network you can run the following:

```bash
docker run --rm --privileged ghcr.io/webmeshproj/node:latest \
    --global.insecure \
    --global.no-ipv6 \
    --mesh.join-address=bootstrap-node:8443
```

The two containers should now be connected to each other over WireGuard and you can exec into them to test connectivity.

The `wmctl` utility included in this repository can also be used to connect and/or query the APIs.
More documentation on the CLI utility will be added soon.

```bash
wmctl connect --insecure --no-ipv6 --join-server=<container_ip>:8443
```

Configuration can be provided as CLI flags (as shown above) or via a configuration file and environment variables.
Full details can be found in the [configuration](doc/configuration.md) docs.

## Building

The `Makefile` contains several targets for building the project.
Since the project uses CGO, it is recommended to build the project in a container with static libraries.
The helpers in the `Makefile` will do this for you when building for distribution.
You can run `make help` to see all the available targets.

## Roadmap

- [ ] Add Windows Support.
- [ ] Potential SaaS offering for those who don't want to run their own controllers or have a simple off-site backup of the mesh state.
- [ ] Ability to peer with other meshes. This would allow for a mesh to be split into multiple smaller meshes that can still communicate with each other.

Most other functionality that is provided by other similar projects already exists in the kernel or in other projects.
For example, NAT64 and DNS64 have several ways of being configured, but could still be seen as a potential common use-case.
There is a question as to how many of those things should be "auto-configured" by a node and how much should be left up to the user.

## Contributing

Contributions are welcome and encouraged.
Please see the [contributing](CONTRIBUTING.md) docs for more information.

## Special Thanks

The developers of [rqlite](https://github.com/rqlite/rqlite) for inspiration on managing a distributed to SQLite.

## Legal

WireGuard is a registered trademark of Jason A. Donenfeld.
