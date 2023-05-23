# Webmesh Node

TODO: Documentation on purpose, usage, examples, etc.

## Command Usage

```sh
Usage: node [flags]
```

The webmesh node is a single node in a webmesh cluster. It is responsible for
tracking the cluster state, managing network configurations, and providing a
gRPC API for other nodes to interact with the cluster. The API is also used by
the webmesh CLI to interact with the cluster.

The node can be configured to bootstrap a new cluster or join an existing
cluster. When bootstrapping a new cluster, the node will become the leader of
the cluster. When joining an existing cluster, the node will attempt to join
the cluster by contacting the leader. Optionally, the node can be configured to
bootstrap with a set of initial nodes. When bootstrapping with initial nodes,
the node will become the leader of the cluster if the initial nodes are not
already part of a cluster. If the initial nodes are already part of a cluster,
the node will join the cluster by contacting the leader of the cluster.

Configuration is available via command line flags, environment variables, and
configuration files. The configuration is parsed in the following order:

- Environment Variables
- Command Line Flags
- Configuration File

Environment variables match the command line flags where all characters are
uppercased and dashes and dots are replaced with underscores. For example, the
command line flag "store.stream-layer.listen-address" would be set via the
environment variable "STORE_STREAM_LAYER_LISTEN_ADDRESS".

Configuration files can be in YAML, JSON, or TOML. The configuration file is
specified via the "--config" flag. The configuration file matches the structure
of the command line flags. For example, the following YAML configuration would
be equivalent to the shown command line flag:

```yaml
# config.yaml
store:
  stream-layer:
    # --store.stream-layer.listen-address
    listen-address: 127.0.0.1
```

```bsh
Global Configurations:

    --global.insecure                (default: false)    Disable use of TLS globally.
    --global.log-level               (default: info)     Log level (debug, info, warn, error)
    --global.mtls                    (default: false)    Enable mutual TLS globally.
    --global.no-ipv4                 (default: false)    Disable use of IPv4 globally.
    --global.no-ipv6                 (default: false)    Disable use of IPv6 globally.
    --global.skip-verify-hostname    (default: false)    Disable hostname verification globally.
    --global.tls-ca-file                                 The CA file for TLS connections.
    --global.tls-cert-file                               The certificate file for TLS connections.
    --global.tls-client-ca-file                          The client CA file for TLS connections.
    --global.tls-key-file                                The key file for TLS connections.

Raft Store Configurations:


    --store.advertise-address    (default: localhost:9443)    Raft advertise address. Required when bootstrapping a new cluster,
                                                              but will be replaced with the wireguard address after bootstrapping.

    --store.apply-timeout             (default: 10s)              Raft apply timeout.
    --store.bootstrap                 (default: false)            Bootstrap the cluster.
    --store.bootstrap-ipv4-network    (default: 172.16.0.0/12)    IPv4 network of the mesh to write to the database when bootstraping a new cluster.

    --store.bootstrap-servers        Comma separated list of servers to bootstrap with. This is only used if bootstrap is true.
                                     If empty, the node will use the advertise address as the bootstrap server. If not empty,
                                     all nodes in the list should be started with the same list and bootstrap-ipv4-network. If the
                                     bootstrap-ipv4-network is not the same, the first node to become leader will pick it.
                                     Servers should be in the form of <node-id>=<address> where address is the advertise address.


    --store.bootstrap-servers-grpc-ports        Comma separated list of gRPC ports to bootstrap with. This is only used
                                                if bootstrap is true. If empty, the node will use the advertise address and
                                                locally configured gRPC port for every node in bootstrap-servers.
                                                Ports should be in the form of <node-id>=<port>.

    --store.commit-timeout           (default: 15s)                       Raft commit timeout.
    --store.connection-pool-count    (default: 0)                         Raft connection pool count.
    --store.connection-timeout       (default: 2s)                        Raft connection timeout.
    --store.data-dir                 (default: /var/lib/webmesh/store)    Store data directory.
    --store.election-timeout         (default: 2s)                        Raft election timeout.
    --store.force-bootstrap          (default: false)                     Force bootstrapping a new cluster even if data is present.
    --store.grpc-advertise-port      (default: 8443)                      GRPC advertise port.
    --store.heartbeat-timeout        (default: 2s)                        Raft heartbeat timeout.
    --store.join                                                          Address of a node to join.
    --store.join-as-voter            (default: false)                     Join the cluster as a voter. Default behavior is to join as an observer.
    --store.join-timeout             (default: 1m0s)                      Join timeout.
    --store.leader-lease-timeout     (default: 2s)                        Raft leader lease timeout.
    --store.max-append-entries       (default: 16)                        Raft max append entries.
    --store.max-join-retries         (default: 10)                        Maximum number of join retries.
    --store.no-ipv4                  (default: false)                     Disable IPv4 for the raft transport.
    --store.no-ipv6                  (default: false)                     Disable IPv6 for the raft transport.

    --store.node-id    (default: <hostname>)    Store node ID. If not set, the ID comes from the following decision tree.
                                                    1. If mTLS is enabled, the node ID is the CN of the client certificate.
                                                    2. If mTLS is not enabled, the node ID is the hostname of the machine.
                                                    3. If the hostname is not available, the node ID is a random UUID (should only be used for testing).

    --store.observer-chan-buffer    (default: 100)      Raft observer channel buffer size.
    --store.raft-log-level          (default: info)     Raft log level.
    --store.raft-prefer-ipv6        (default: false)    Prefer IPv6 when connecting to raft peers.
    --store.snapshot-interval       (default: 5m0s)     Raft snapshot interval.
    --store.snapshot-retention      (default: 3)        Raft snapshot retention.
    --store.snapshot-threshold      (default: 50)       Raft snapshot threshold.

Raft Stream Layer Configurations:

    --store.stream-layer.insecure                (default: false)    Don't use TLS for the stream layer.
    --store.stream-layer.listen-address          (default: :9443)    Stream layer listen address.
    --store.stream-layer.mtls                    (default: false)    Enable mutual TLS for the stream layer.
    --store.stream-layer.skip-verify-hostname    (default: false)    Skip hostname verification for the stream layer.
    --store.stream-layer.tls-ca-file                                 Stream layer TLS CA file.
    --store.stream-layer.tls-cert-file                               Stream layer TLS certificate file.
    --store.stream-layer.tls-client-ca-file                          Stream layer TLS client CA file.
    --store.stream-layer.tls-key-file                                Stream layer TLS key file.

gRPC Server Configurations:

    --grpc.disable-leader-proxy      (default: false)       Disable the leader proxy.
    --grpc.enable-metrics            (default: false)       Enable gRPC metrics.
    --grpc.insecure                  (default: false)       Don't use TLS for the gRPC server.
    --grpc.listen-address            (default: :8443)       gRPC server listen address.
    --grpc.metrics-listen-address    (default: :8080)       gRPC metrics listen address.
    --grpc.metrics-path              (default: /metrics)    gRPC metrics path.
    --grpc.mtls                      (default: false)       Enable mutual TLS.
    --grpc.skip-verify-hostname      (default: false)       Skip hostname verification.
    --grpc.tls-ca-file                                      gRPC server TLS CA file.
    --grpc.tls-cert-file                                    gRPC server TLS certificate file.
    --grpc.tls-client-ca-file                               gRPC server TLS client CA file.
    --grpc.tls-key-file                                     gRPC server TLS key file.

WireGuard Configurations:

    --wireguard.endpoint                           The wireguard endpoint. If unset, inbound tunnels will not be accepted.
    --wireguard.force-name     (default: false)    Force the use of the given name by deleting any pre-existing interface with the same name.
    --wireguard.force-tun      (default: false)    Force the use of a TUN interface.
    --wireguard.listen-port    (default: 51820)    The wireguard listen port.
    --wireguard.masquerade     (default: false)    Masquerade traffic from the wireguard interface.
    --wireguard.name           (default: wg0)      The wireguard interface name.
    --wireguard.no-modprobe    (default: false)    Don't attempt to probe the wireguard module.

General Flags

  --config         Load flags from the given configuration file
  --print-config   Print the configuration and exit

  --help       Show this help message
  --version    Show version information and exit
```
