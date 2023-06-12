# Confiuration

For now this is just the help output from running the node with no arguments.
It explains the flags and environment variables that can be used to configure the node.

The configuration file can be in YAML, JSON, or TOML format and is specified via the `--config` flag.
It is rendered as a go-template first, with the following additional methods:

- `env` - Returns the value of the environment variable with the given name.
- `file` - Returns the contents of the file with the given name.

```bash
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
command line flag "mesh.node-id" would be set via the environment variable
"MESH_NODE_ID".

Configuration files can be in YAML, JSON, or TOML. The configuration file is
specified via the "--config" flag. The configuration file matches the structure
of the command line flags. For example, the following YAML configuration would
be equivalent to the shown command line flag:

  # config.yaml
  mesh:
    node-id: "node-1"  # --mesh.node-id="node-1"

Global Configurations:

    --global.allow-remote-detection      (default: false)    Allow remote detection of endpoints.
    --global.detect-endpoints            (default: false)    Detect potential endpoints from the local interfaces.
    --global.detect-ipv6                 (default: false)    Detect IPv6 addresses. Default is to only detect IPv4.
    --global.detect-private-endpoints    (default: false)    Include private IP addresses in detection.
    --global.insecure                    (default: false)    Disable use of TLS globally.
    --global.log-level                   (default: info)     Log level (debug, info, warn, error)
    --global.mtls                        (default: false)    Enable mutual TLS for authentication.
    --global.no-ipv4                     (default: false)    Disable use of IPv4 globally.
    --global.no-ipv6                     (default: false)    Disable use of IPv6 globally.

    --global.primary-endpoint        The preferred publicly routable address of this node. Setting this
                                     value will override the address portion of the store advertise address.
                                     When detect-endpoints is true, this value will be the first address detected.

    --global.tls-ca-file                               The CA file for TLS connections.
    --global.tls-cert-file                             The certificate file for TLS connections.
    --global.tls-client-ca-file                        The client CA file for TLS connections.
    --global.tls-key-file                              The key file for TLS connections.
    --global.verify-chain-only     (default: false)    Only verify the TLS chain globally.

Mesh Configurations:

    --mesh.grpc-port                (default: 8443)        GRPC advertise port.
    --mesh.join-address                                    Address of a node to join.
    --mesh.join-as-voter            (default: false)       Join the cluster as a voter. Default behavior is to join as an observer.
    --mesh.join-timeout             (default: 1m0s)        Join timeout.
    --mesh.key-rotation-interval    (default: 168h0m0s)    Interval to rotate WireGuard keys. Set this to 0 to disable key rotation.
    --mesh.max-join-retries         (default: 10)          Maximum number of join retries.
    --mesh.no-ipv4                  (default: false)       Do not request IPv4 assignments when joining.
    --mesh.no-ipv6                  (default: false)       Do not request IPv6 assignments when joining.

    --mesh.node-id    (default: <hostname>)    Store node ID. If not set, the ID comes from the following decision tree.
                                               1. If mTLS is enabled, the node ID is the CN of the client certificate.
                                               2. If mTLS is not enabled, the node ID is the hostname of the machine.
                                               3. If the hostname is not available, the node ID is a random UUID (should only be used for testing).

    --mesh.peer-discovery-addresses        Addresses to use for peer discovery.

    --mesh.primary-endpoint        The primary endpoint to broadcast when joining a cluster.
                                   This is only necessary if the node intends on being publicly accessible.


    --mesh.routes        Comma separated list of additional routes to advertise to the mesh.
                             These routes are advertised to all peers. If the node is not allowed
                             to put routes in the mesh, the node will be unable to join.

    --mesh.wireguard-endpoints        Comma separated list of additional WireGuard endpoints to broadcast when joining a cluster.
    --mesh.zone-awareness-id          Zone awareness ID. If set, the server will prioritize peer endpoints in the same zone.

Authentication Configurations:

    --auth.basic.password        A password to use for basic auth.
    --auth.basic.username        A username to use for basic auth.
    --auth.ldap.password         A password to use for LDAP auth.
    --auth.ldap.username         A username to use for LDAP auth.
    --auth.mtls.cert-file        The path to a TLS certificate file to present when joining.
    --auth.mtls.key-file         The path to a TLS key file for the certificate.

Bootstrap Configurations:

    --bootstrap.admin    (default: admin)    Admin username to bootstrap the cluster with.

    --bootstrap.advertise-address        Raft advertise address. Required when bootstrapping a new cluster,
                                         but will be replaced with the WireGuard address after bootstrapping.

    --bootstrap.default-network-policy    (default: deny)             Default network policy to bootstrap the cluster with.
    --bootstrap.enabled                   (default: false)            Bootstrap the cluster.
    --bootstrap.force                     (default: false)            Force bootstrapping a new cluster even if data is present.
    --bootstrap.ipv4-network              (default: 172.16.0.0/12)    IPv4 network of the mesh to write to the database when bootstraping a new cluster.

    --bootstrap.servers        Comma separated list of servers to bootstrap with. This is only used if bootstrap is true.
                               If empty, the node will use the advertise address as the bootstrap server. If not empty,
                               all nodes in the list should be started with the same list configurations. If any are
                               different then the first node to become leader will pick them. This can cause bootstrap
                               to fail when using ACLs. Servers should be in the form of <node-id>=<address> where
                               address is the raft advertise address.


    --bootstrap.servers-grpc-ports        Comma separated list of gRPC ports to bootstrap with. This is only used
                                          if bootstrap is true. If empty, the node will use the advertise address and
                                          locally configured gRPC port for every node in bootstrap-servers.
                                          Ports should be in the form of <node-id>=<port>.

    --bootstrap.voters        Comma separated list of voters to bootstrap the cluster with. bootstrap-servers are already included in this list.

Raft Configurations:

    --raft.apply-timeout            (default: 15s)                       Raft apply timeout.
    --raft.commit-timeout           (default: 15s)                       Raft commit timeout.
    --raft.connection-pool-count    (default: 0)                         Raft connection pool count.
    --raft.connection-timeout       (default: 3s)                        Raft connection timeout.
    --raft.data-dir                 (default: /var/lib/webmesh/store)    Store data directory.
    --raft.election-timeout         (default: 3s)                        Raft election timeout.
    --raft.heartbeat-timeout        (default: 3s)                        Raft heartbeat timeout.
    --raft.in-memory                (default: false)                     Store data in memory. This should only be used for testing and ephemeral nodes.
    --raft.leader-lease-timeout     (default: 3s)                        Raft leader lease timeout.
    --raft.leave-on-shutdown        (default: false)                     Leave the cluster when the server shuts down.
    --raft.listen-address           (default: :9443)                     Raft listen address.

    --raft.log-format    (default: protobuf+snappy)    Raft log format. Valid options are 'json', 'protobuf', and 'protobuf+snappy'.
                                                       All nodes must use the same log format for the lifetime of the cluster.

    --raft.log-level               (default: info)     Raft log level.
    --raft.max-append-entries      (default: 16)       Raft max append entries.
    --raft.observer-chan-buffer    (default: 100)      Raft observer channel buffer size.
    --raft.prefer-ipv6             (default: false)    Prefer IPv6 when connecting to raft peers.
    --raft.shutdown-timeout        (default: 1m0s)     Timeout for graceful shutdown.
    --raft.snapshot-interval       (default: 5m0s)     Raft snapshot interval.
    --raft.snapshot-retention      (default: 3)        Raft snapshot retention.
    --raft.snapshot-threshold      (default: 50)       Raft snapshot threshold.
    --raft.startup-timeout         (default: 3m0s)     Timeout for startup.

TLS Configurations:

    --tls.ca-file                                     Stream layer TLS CA file.
    --tls.insecure                (default: false)    Don't use TLS for the stream layer.
    --tls.insecure-skip-verify    (default: false)    Skip verification of the stream layer certificate.
    --tls.verify-chain-only       (default: false)    Only verify the certificate chain for the stream layer.

WireGuard Configurations:


    --wireguard.endpoint-overrides        EndpointOverrides is a map of peer IDs to endpoint overrides.
                                          The format is similar to allowed-ips, but the value is a single endpoint.

    --wireguard.force-interface-name    (default: false)       Force the use of the given name by deleting any pre-existing interface with the same name.
    --wireguard.force-tun               (default: false)       Force the use of a TUN interface.
    --wireguard.interface-name          (default: webmesh0)    The WireGuard interface name.
    --wireguard.listen-port             (default: 51820)       The WireGuard listen port.
    --wireguard.masquerade              (default: false)       Masquerade traffic from the WireGuard interface.
    --wireguard.modprobe                (default: false)       Attempt to load the WireGuard kernel module.
    --wireguard.mtu                     (default: 1350)        The MTU to use for the interface.

    --wireguard.persistent-keepalive    (default: 0s)    PersistentKeepAlive is the interval at which to send keepalive packets
                                                         to peers. If unset, keepalive packets will automatically be sent to publicly
                                                         accessible peers when this instance is behind a NAT. Otherwise, no keep-alive
                                                         packets are sent.


Service Configurations:

    --services.api.admin                         (default: false)                           Enable the admin API.
    --services.api.leader-proxy                  (default: false)                           Enable the leader proxy.
    --services.api.mesh                          (default: false)                           Enable the mesh API.
    --services.api.peer-discovery                (default: false)                           Enable the peer discovery API.
    --services.api.proxy-insecure                (default: false)                           Don't use TLS for the leader proxy.
    --services.api.proxy-insecure-skip-verify    (default: false)                           Skip TLS verification when proxying connections.
    --services.api.proxy-tls-ca-file                                                        Path to the TLS CA file for verifying the peer certificates.
    --services.api.proxy-tls-cert-file                                                      Path to the TLS certificate file for proxying.
    --services.api.proxy-tls-key-file                                                       Path to the TLS key file for proxying.
    --services.api.proxy-verify-chain-only       (default: false)                           Only verify the TLS chain when proxying connections.
    --services.api.stun-servers                  (default: stun:stun.l.google.com:19302)    STUN servers to use.
    --services.api.webrtc                        (default: false)                           Enable the WebRTC API.
    --services.insecure                          (default: false)                           Don't use TLS for the gRPC server.
    --services.listen-address                    (default: :8443)                           gRPC server listen address.
    --services.mesh-dns.domain                   (default: webmesh.internal)                Domain to use for mesh DNS.
    --services.mesh-dns.enable-compression       (default: true)                            Enable DNS compression for mesh DNS.
    --services.mesh-dns.enabled                  (default: false)                           Enable mesh DNS.
    --services.mesh-dns.listen-tcp               (default: :5353)                           TCP address to listen on for DNS requests.
    --services.mesh-dns.listen-udp               (default: :5353)                           UDP address to listen on for DNS requests.
    --services.mesh-dns.request-timeout          (default: 5s)                              Timeout for mesh DNS requests.
    --services.mesh-dns.reuse-port               (default: 0)                               Enable SO_REUSEPORT for mesh DNS.
    --services.mesh-dns.tsig-key                                                            TSIG key to use for mesh DNS.
    --services.metrics.enabled                   (default: false)                           Enable gRPC metrics.
    --services.metrics.listen-address            (default: :8080)                           gRPC metrics listen address.
    --services.metrics.path                      (default: /metrics)                        gRPC metrics path.
    --services.tls-cert-file                                                                gRPC server TLS certificate file.
    --services.tls-key-file                                                                 gRPC server TLS key file.
    --services.turn.enabled                      (default: false)                           Enable the TURN server.
    --services.turn.endpoint                                                                The TURN server endpoint. If empty, the public IP will be used.
    --services.turn.listen-address               (default: 0.0.0.0)                         Address to listen on for TURN connections.
    --services.turn.listen-port                  (default: 3478)                            Port to listen on for TURN connections.
    --services.turn.public-ip                                                               The address advertised for STUN requests.
    --services.turn.server-realm                 (default: webmesh.io)                      Realm used for TURN server authentication.
    --services.turn.stun-port-range              (default: 49152-65535)                     Port range to use for STUN.

General Flags

  --config         Load flags from the given configuration file
  --print-config   Print the configuration and exit

  --help       Show this help message
  --version    Show version information and exit
```
