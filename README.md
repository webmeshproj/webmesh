# Webmesh

[![Go Report Card](https://goreportcard.com/badge/github.com/webmeshproj/node)](https://goreportcard.com/report/github.com/webmeshproj/node)
![Build and Tests](https://github.com/webmeshproj/node/actions/workflows/ci.yaml/badge.svg)

Webmesh is a simple, distributed, and zero-configuration WireGuard™ mesh solution for Linux, FreeBSD, macOS, and Windows.
It is designed to be easy to use, and to work well with existing network infrastructure.
For a more detailed introduction and extended documentation, please see the [project website](https://webmeshproj.github.io).

This repository contains the core functionality of the Webmesh Project.
It implements the [Webmesh API](https://github.com/webmeshproj/api) in Go.

**This project is not yet ready for production use, but I hope to rapidly get there. For now, expect backwards-incompatible changes.**

## Getting Started

If you'd like to play with the project on Kubernetes, there is a work-in-progress Operator in the [operator](https://github.com/webmeshproj/operator/) repository.
It works fine on most clusters, including ephemeral docker-based ones, but is not yet ready for production use.

Detailed instructions can be found in the [Getting Started](https://webmeshproj.github.io/documentation/getting-started/) guide on the project website.

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
Full details can be found on the [configuration section](https://webmeshproj.github.io/documentation/configuration/) of the project website.
Administration of the network can be done via the [API](https://webmeshproj.github.io/documentation/administration/) using the CLI or custom tooling.

## Building

The `Makefile` contains several targets for building the project.
Since the project uses CGO, it is recommended to build the project in a container with static libraries.
The helpers in the `Makefile` will do this for you when building for distribution.
You can run `make help` to see all the available targets.It looks very interesting, but I'm still on the fence about it. It doesn't look so bad in practice without all the theoretical type parameters laid around.

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

## Special Thanks

The developers of [rqlite](https://github.com/rqlite/rqlite) for inspiration on managing a distributed database.

The incredible work done by the [pion](https://github.com/pion/webrtc) team for WebRTC in Go.

## Legal

WireGuard is a registered trademark of Jason A. Donenfeld.

## Support

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/webmeshproj)
