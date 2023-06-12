# Webmesh Node

This repository contains the core functionality of the Webmesh Project.
It implements the [API](https://github.com/webmeshproj/api) in Go.

This project aims to provide distributed and decentralized communication for devices and services across the internet.
It is inspired by several other projects that have emerged over the years such as TailScale, ZeroTier, and OpenZiti.
The core difference, however, is that every node in the network is also, optionally, a controller server.
Another core aim is to offload as much networking onto pre-existing protocols as possible and strive to maintain a simple codebase.
This is one of the reasons the project is built on top of [WireGuard](https://www.wireguard.com/).

Nodes connected to the network take on one of three roles. They can be a client, a server, or both.
A client is a node that is connected to the network but does not provide any services, except to itself.
A server is a node that is connected to the network and provides services to other nodes.
When a server node is also the leader, it is referred to as a controller.
Other server nodes will proxy requests to mutate the network to the controller.
State is maintained on every connected node via Raft consensus.
This allows for the network to be highly available and fault tolerant.

Examples of different topologies and usages can be found in the [examples](examples/) directory.
More examples and documentation will be added as the project matures.

## Getting Started

## Building

## Contributing

## Special Thanks

The developers of [rqlite](https://github.com/rqlite/rqlite) for inspiration on managing a distributed to SQLite.

## Legal

WireGuard is a registered trademark of Jason A. Donenfeld.
