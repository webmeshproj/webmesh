# Webmesh

[![Go Report Card](https://goreportcard.com/badge/github.com/webmeshproj/webmesh)](https://goreportcard.com/report/github.com/webmeshproj/webmesh)
![Build and Tests](https://github.com/webmeshproj/webmesh/actions/workflows/ci.yaml/badge.svg)

Webmesh is a simple, distributed, and zero-configuration WireGuard™ mesh solution for Linux, FreeBSD, macOS, and Windows.
It allows for easily creating a mesh network between multiple hosts, and provides a simple API for managing the network.
It is designed to be easy to use, and to work well with existing network infrastructure.
For a more detailed introduction and extended documentation, please see the [project website](https://webmeshproj.github.io).

This repository contains the core functionality of the Webmesh Project.
It implements the [Webmesh API](https://github.com/webmeshproj/api) in Go.

**This project is not yet ready for production use, but I hope to rapidly get there. For now, expect backwards-incompatible changes.**

## Getting Started

Detailed instructions can be found in the [Getting Started](https://webmeshproj.github.io/documentation/getting-started/) guide on the project website.
Examples of different topologies and the various features available, see the [examples](examples/) directory.

If you'd like to play with the project on Kubernetes, there is a work-in-progress Operator in the [operator](https://github.com/webmeshproj/operator/) repository.
It works fine on most clusters, including ephemeral docker-based ones, but is not yet ready for production use.

## Building

The `Makefile` contains several targets for building the project.
You can run `make help` to see all the available targets.

## Roadmap

- [ ] GUI Application. In the works over [here](https://github.com/webmeshproj/app).
- [ ] Potential SaaS offering for those who don't want to run their own controllers or have a simple off-site backup of the mesh state.
- [ ] Ability to peer with other meshes. This would allow for a mesh to be split into multiple smaller meshes that can still communicate with each other.

Most other functionality that is provided by other similar projects already exists in the kernel or in other projects.
For example, NAT64 and DNS64 have several ways of being configured, but could still be seen as a potential common use-case.
There is a question as to how many of those things should be "auto-configured" by a node and how much should be left up to the user.

## Contributing

Contributions are welcome and encouraged.
Please see the [contributing](CONTRIBUTING.md) docs for more information.

## Community

Join me in the [webmesh](https://gophers.slack.com/archives/C05L44ZFG80) channel on the Gophers Slack.

## Special Thanks

The developers of [rqlite](https://github.com/rqlite/rqlite) for inspiration on managing a distributed database.

The incredible work done by the [pion](https://github.com/pion/webrtc) team for WebRTC in Go.

## Legal

WireGuard is a registered trademark of Jason A. Donenfeld.

## Support

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/webmeshproj)
