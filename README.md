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

```bash
Global Configurations:

    --global.allow-remote-detection      (default: false)    Allow remote detection of endpoints.
    --global.detect-endpoints            (default: false)    Detect potential endpoints from the local interfaces.
    --global.detect-ipv6                 (default: false)    Detect IPv6 addresses. Default is to only detect IPv4.
    --global.detect-private-endpoints    (default: false)    Include private IP addresses in detection.

    --global.endpoints        A comma separated list of additional endpoints to advertise. These
                              are merged with existing endpoints in the other configurations.

    --global.insecure     (default: false)    Disable use of TLS globally.
    --global.log-level    (default: info)     Log level (debug, info, warn, error)
    --global.mtls         (default: false)    Enable mutual TLS globally.
    --global.no-ipv4      (default: false)    Disable use of IPv4 globally.
    --global.no-ipv6      (default: false)    Disable use of IPv6 globally.

    --global.primary-endpoint        The preferred publicly routable address of this node. Setting this
                                     value will override the address portion of the store advertise address
                                     and WireGuard endpoints. This is only necessary if you intend for
                                     this node's API to be reachable outside the network.

    --global.skip-verify-hostname    (default: false)    Disable hostname verification globally.
    --global.tls-ca-file                                 The CA file for TLS connections.
    --global.tls-cert-file                               The certificate file for TLS connections.
    --global.tls-client-ca-file                          The client CA file for TLS connections.
    --global.tls-key-file                                The key file for TLS connections.

Raft Store Configurations:


    --store.advertise-address    (default: localhost:9443)    Raft advertise address. Required when bootstrapping a new cluster,
                                                              but will be replaced with the WireGuard address after bootstrapping.

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

    --store.commit-timeout               (default: 15s)                       Raft commit timeout.
    --store.connection-pool-count        (default: 0)                         Raft connection pool count.
    --store.connection-timeout           (default: 2s)                        Raft connection timeout.
    --store.data-dir                     (default: /var/lib/webmesh/store)    Store data directory.
    --store.election-timeout             (default: 2s)                        Raft election timeout.
    --store.force-bootstrap              (default: false)                     Force bootstrapping a new cluster even if data is present.
    --store.grpc-advertise-port          (default: 8443)                      GRPC advertise port.
    --store.heartbeat-timeout            (default: 2s)                        Raft heartbeat timeout.
    --store.in-memory                    (default: false)                     Store data in memory. This should only be used for testing and ephemeral nodes.
    --store.join                                                              Address of a node to join.
    --store.join-as-voter                (default: false)                     Join the cluster as a voter. Default behavior is to join as an observer.
    --store.join-timeout                 (default: 1m0s)                      Join timeout.
    --store.key-rotation-interval        (default: 168h0m0s)                  Interval to rotate WireGuard keys. Set this to 0 to disable key rotation.
    --store.leader-lease-timeout         (default: 2s)                        Raft leader lease timeout.
    --store.max-append-entries           (default: 16)                        Raft max append entries.
    --store.max-join-retries             (default: 10)                        Maximum number of join retries.
    --store.no-ipv4                      (default: false)                     Disable IPv4 for the raft transport.
    --store.no-ipv6                      (default: false)                     Disable IPv6 for the raft transport.
    --store.node-additional-endpoints                                         Comma separated list of additional endpoints to broadcast to the cluster.

    --store.node-endpoint        NodeEndpoint is the endpoint to broadcast when joining a cluster.
                                 This is only necessary if the node intends on exposing it's API. When
                                 bootstrapping a cluster with a node that has an empty NodeEndpoint, the
                                 node will use the AdvertiseAddress as the NodeEndpoint.


    --store.node-id    (default: <hostname>)    Store node ID. If not set, the ID comes from the following decision tree.
                                                    1. If mTLS is enabled, the node ID is the CN of the client certificate.
                                                    2. If mTLS is not enabled, the node ID is the hostname of the machine.
                                                    3. If the hostname is not available, the node ID is a random UUID (should only be used for testing).

    --store.observer-chan-buffer     (default: 100)     Raft observer channel buffer size.
    --store.peer-refresh-interval    (default: 1m0s)    Interval to refresh WireGuard peer list.

    --store.raft-log-format    (default: protobuf+snappy)    Raft log format. Valid options are 'json', 'protobuf', and 'protobuf+snappy'.
                                                             All nodes must use the same log format for the lifetime of the cluster.

    --store.raft-log-level        (default: info)     Raft log level.
    --store.raft-prefer-ipv6      (default: false)    Prefer IPv6 when connecting to raft peers.
    --store.shutdown-timeout      (default: 1m0s)     Timeout for graceful shutdown.
    --store.snapshot-interval     (default: 5m0s)     Raft snapshot interval.
    --store.snapshot-retention    (default: 3)        Raft snapshot retention.
    --store.snapshot-threshold    (default: 50)       Raft snapshot threshold.

Raft Stream Layer Configurations:

    --store.stream-layer.insecure                (default: false)    Don't use TLS for the stream layer.
    --store.stream-layer.listen-address          (default: :9443)    Stream layer listen address.
    --store.stream-layer.mtls                    (default: false)    Enable mutual TLS for the stream layer.
    --store.stream-layer.skip-verify-hostname    (default: false)    Skip hostname verification for the stream layer.
    --store.stream-layer.tls-ca-file                                 Stream layer TLS CA file.
    --store.stream-layer.tls-cert-file                               Stream layer TLS certificate file.
    --store.stream-layer.tls-client-ca-file                          Stream layer TLS client CA file.
    --store.stream-layer.tls-key-file                                Stream layer TLS key file.

Service Configurations:

    --services.enable-leader-proxy          (default: false)    Enable the leader proxy.
    --services.enable-mesh-api              (default: false)    Enable the mesh API.
    --services.enable-mesh-dns              (default: false)    Enable the mesh DNS server.
    --services.enable-metrics               (default: false)    Enable gRPC metrics.
    --services.enable-peer-discovery-api    (default: false)    Enable the peer discovery API.
    --services.enable-turn-server           (default: false)    Enable the TURN server.
    --services.enable-webrtc-api            (default: false)    Enable the WebRTC API.

    --services.exclusive-turn-server    (default: false)    Replace all stun-servers with the local TURN server.
                                                            The equivalent of stun-servers=stun:<turn-server-public-ip>:<turn-server-port>.

    --services.grpc-listen-address           (default: :8443)                           gRPC server listen address.
    --services.insecure                      (default: false)                           Don't use TLS for the gRPC server.
    --services.mesh-dns-compression          (default: true)                            Enable DNS compression for mesh DNS.
    --services.mesh-dns-domain               (default: webmesh.internal)                Domain to use for mesh DNS.
    --services.mesh-dns-listen-tcp           (default: :5353)                           TCP address to listen on for DNS requests.
    --services.mesh-dns-listen-udp           (default: :5353)                           UDP address to listen on for DNS requests.
    --services.mesh-dns-request-timeout      (default: 5s)                              Timeout for mesh DNS requests.
    --services.mesh-dns-reuse-port           (default: 0)                               Enable SO_REUSEPORT for mesh DNS.
    --services.mesh-dns-tsig-key                                                        TSIG key to use for mesh DNS.
    --services.metrics-listen-address        (default: :8080)                           gRPC metrics listen address.
    --services.metrics-path                  (default: /metrics)                        gRPC metrics path.
    --services.mtls                          (default: false)                           Enable mutual TLS.
    --services.skip-verify-hostname          (default: false)                           Skip hostname verification.
    --services.stun-port-range               (default: 49152-65535)                     Port range to use for STUN.
    --services.stun-servers                  (default: stun:stun.l.google.com:19302)    STUN servers to use.
    --services.tls-ca-file                                                              gRPC server TLS CA file.
    --services.tls-cert-file                                                            gRPC server TLS certificate file.
    --services.tls-client-ca-file                                                       gRPC server TLS client CA file.
    --services.tls-key-file                                                             gRPC server TLS key file.
    --services.turn-server-endpoint                                                     The TURN server endpoint. If empty, the public IP will be used.
    --services.turn-server-listen-address    (default: 0.0.0.0)                         Address to listen on for TURN connections.
    --services.turn-server-port              (default: 3478)                            Port to listen on for TURN connections.
    --services.turn-server-public-ip                                                    The address advertised for STUN requests.
    --services.turn-server-realm             (default: webmesh.io)                      Realm used for TURN server authentication.

WireGuard Configurations:


    --wireguard.allowed-ips        AllowedIPs is a map of peers to allowed IPs. The peers can either be
                                   peer IDs or regexes matching peer IDs. These IP addresses should not overlap
                                   with the private network of the WireGuard interface. AllowedIPs in this context
                                   refers to the IP addresses that this instance will route to the peer. The peer
                                   will also need to configure AllowedIPs for this instance's IP address.

                                   The format is a whitespace separated list of key-value pairs, where the key is
                                   the peer to match and the value is a comman-separated list of IP CIDRs.
                                   For example:

                                       # Peer names
                                       --wireguard.allowed-ips="peer1=10.0.0.0/24,10.0.1.0/24 peer2="10.0.2.0/24"
                                       # Peer regexes
                                       --wireguard.allowed-ips="peer.*=10.0.0.0/16"



    --wireguard.endpoint-overrides        EndpointOverrides is a map of peer IDs to endpoint overrides.
                                          The format is similar to allowed-ips, but the value is a single endpoint.

    --wireguard.force-name     (default: false)    Force the use of the given name by deleting any pre-existing interface with the same name.
    --wireguard.force-tun      (default: false)    Force the use of a TUN interface.
    --wireguard.listen-port    (default: 51820)    The WireGuard listen port.
    --wireguard.masquerade     (default: false)    Masquerade traffic from the WireGuard interface.
    --wireguard.modprobe       (default: false)    Attempt to load the WireGuard kernel module.
    --wireguard.name           (default: wg0)      The WireGuard interface name.

    --wireguard.persistent-keepalive    (default: 0s)    PersistentKeepAlive is the interval at which to send keepalive packets
                                                         to peers. If unset, keepalive packets will automatically be sent to publicly
                                                         accessible peers when this instance is behind a NAT. Otherwise, no keep-alive
                                                         packets are sent.


General Flags

  --config         Load flags from the given configuration file
  --print-config   Print the configuration and exit

  --help       Show this help message
  --version    Show version information and exit
```

## Special Thanks

The developers of [rqlite](https://github.com/rqlite/rqlite) for inspiration on managing a distributed to SQLite.

## Legal

WireGuard is a registered trademark of Jason A. Donenfeld.
