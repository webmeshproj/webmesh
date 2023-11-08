<h1 style="text-align: left"><img align="center" height="50" src="img/webmesh.png" style="margin-top: -7px;">Webmesh</h1>

[![Go Report Card](https://goreportcard.com/badge/github.com/webmeshproj/webmesh)](https://goreportcard.com/report/github.com/webmeshproj/webmesh)
![Build and Tests](https://github.com/webmeshproj/webmesh/actions/workflows/ci.yaml/badge.svg)
[![Go Reference](https://pkg.go.dev/badge/github.com/webmeshproj/webmesh.svg)](https://pkg.go.dev/github.com/webmeshproj/webmesh)
[![Sponsor](https://img.shields.io/static/v1?label=Sponsor&message=%E2%9D%A4&logo=GitHub&color=%23fe8e86)](https://github.com/sponsors/webmeshproj)

Webmesh is a simple, distributed, and zero-configuration WireGuard™ mesh solution for Linux, FreeBSD, macOS, and Windows.
It allows for easily creating a mesh network between multiple hosts, and provides a simple API for managing the network.
It is designed to be easy to use, and to work well with existing network infrastructure.
For a more detailed introduction and extended documentation, please see the [project website](https://webmeshproj.github.io).

Webmesh is not a VPN, but rather a mesh network.
It is designed to be used in conjunction with existing network infrastructure, and not as a replacement for it.
It is also not a replacement for WireGuard™, but rather a way to manage a WireGuard™ mesh network.
Connections are made into the network via direct links, over ICE (WebRTC) connections, or over [LibP2P](https://libp2p.io/) circuit relays.
It differs from other WireGuard™ management solutions in that:

- It is designed to be distributed and extensible, relying on no single controller or database.
- The network is malleable and topology is governed by the user, not the controller.
- A plugin API is provided for adding additional functionality, such as a distributed database for storing the mesh state or additional authentication mechanisms.
- An application API is also provided for interacting with the mesh network, and is used by the CLI and GUI applications.

## Getting Started

If you are looking for the GUI application, you can find it in the [webmesh-app](https://github.com/webmeshproj/webmesh-app) repository.

Detailed instructions can be found in the [Getting Started](https://webmeshproj.github.io/documentation/getting-started/) guide on the project website.
For examples of different topologies and the various features available, see the [examples](examples/) directory.

If you'd like to play with the project on Kubernetes, there is a work-in-progress Operator in the [operator](https://github.com/webmeshproj/operator/) repository.
It works fine on most clusters, including ephemeral docker-based ones, but is not yet ready for production use.

## Building

The `Makefile` contains several targets for building the project.
You can run `make help` to see all the available targets.

## Roadmap

- [ ] More storage provider implementations. Currently only built-in raft storage is supported.
- [ ] Potential SaaS offering for those who don't want to run their own controllers or have a simple off-site backup of the mesh state.

Most other functionality that is provided by other similar projects already exists in the kernel or in other projects.
For example, NAT64 and DNS64 have several ways of being configured, but could still be seen as a potential common use-case.
There is a question as to how many of those things should be "auto-configured" by a node and how much should be left up to the user.

## Contributing

Contributions are welcome and encouraged.
Please see the [contributing](CONTRIBUTING.md) docs for more information.

## Community

Join me on [Discord](https://discord.gg/vpkFjGuwYC) or in the [webmesh](https://gophers.slack.com/archives/C05L44ZFG80) channel on the Gophers Slack.

## Special Thanks

The developers of [rqlite](https://github.com/rqlite/rqlite) for inspiration on managing a distributed database.

The incredible work done by the [pion](https://github.com/pion/webrtc) team for WebRTC in Go.

## Legal

WireGuard is a registered trademark of Jason A. Donenfeld.

## Support

Become a [Github Sponsor](https://github.com/sponsors/webmeshproj).
