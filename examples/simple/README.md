# Simple Example

This example just has a single bootstrap server and a single join node.
None of the optional services are enabled so very limited functionality is available.

## Running

You can run the example with the following command:

```bash
docker-compose up
```

Stop it with:

```
docker-compose down -v
```

Since none of the APIs are enabled very little CLI functionality will work.
But you will be able to query that the nodes are connected with the status command.

```bash
$ wmctl --insecure --server localhost:8443 status
{
  "id":  "bootstrap-node-1",
  "version":  "e96c764-dirty",
  "commit":  "e96c7648c54d2c933e927f37b5298f68ca71153b",
  "buildDate":  "2023-06-12T15:08:11Z",
  "uptime":  "45.973034489s",
  "startedAt":  "2023-06-12T17:47:25.133356536Z",
  "features":  [
    "NODES"
  ],
  "clusterStatus":  "CLUSTER_LEADER",
  "currentLeader":  "bootstrap-node-1",
  "currentTerm":  "2",
  "lastLogIndex":  "19",
  "lastApplied":  "19",
  "interfaceMetrics":  {
    "deviceName":  "webmesh0",
    "publicKey":  "DQEDq3ztzu4Oc/fny1gPUP63b2F1Agx+z1AmG2Y9ZVA=",
    "addressV4":  "172.16.0.1/12",
    "addressV6":  "invalid Prefix",
    "type":  "Linux kernel",
    "listenPort":  51820,
    "totalReceiveBytes":  "50276",
    "totalTransmitBytes":  "80670",
    "numPeers":  1,
    "peers":  [
      {
        "publicKey":  "286sydx+89EeD0TdzkSoJ9cgMFe4wXuoRi/DeuC0XRQ=",
        "endpoint":  "10.1.0.3:51820",
        "persistentKeepAlive":  "30s",
        "lastHandshakeTime":  "2023-06-12T17:47:25Z",
        "allowedIps":  [
          "172.16.0.2/32",
          "fde8:67fb:5960:6f1::/64"
        ],
        "protocolVersion":  "1",
        "receiveBytes":  "50276",
        "transmitBytes":  "80670"
      }
    ]
  }
}

$ wmctl --insecure --server localhost:8443 status join-node
{
  "id":  "join-node",
  "version":  "e96c764-dirty",
  "commit":  "e96c7648c54d2c933e927f37b5298f68ca71153b",
  "buildDate":  "2023-06-12T15:08:11Z",
  "uptime":  "1m4.253771754s",
  "startedAt":  "2023-06-12T17:47:26.480637416Z",
  "features":  [
    "NODES"
  ],
  "clusterStatus":  "CLUSTER_NON_VOTER",
  "currentLeader":  "bootstrap-node-1",
  "currentTerm":  "2",
  "lastLogIndex":  "19",
  "lastApplied":  "19",
  "interfaceMetrics":  {
    "deviceName":  "webmesh0",
    "publicKey":  "286sydx+89EeD0TdzkSoJ9cgMFe4wXuoRi/DeuC0XRQ=",
    "addressV4":  "172.16.0.2/12",
    "addressV6":  "invalid Prefix",
    "type":  "Linux kernel",
    "listenPort":  51820,
    "totalReceiveBytes":  "112446",
    "totalTransmitBytes":  "71412",
    "numPeers":  1,
    "peers":  [
      {
        "publicKey":  "DQEDq3ztzu4Oc/fny1gPUP63b2F1Agx+z1AmG2Y9ZVA=",
        "endpoint":  "10.1.0.2:51820",
        "persistentKeepAlive":  "30s",
        "lastHandshakeTime":  "2023-06-12T17:47:25Z",
        "allowedIps":  [
          "172.16.0.1/32",
          "fde8:67fb:5960:f516::/64"
        ],
        "protocolVersion":  "1",
        "receiveBytes":  "112446",
        "transmitBytes":  "71412"
      }
    ]
  }
}
```

You can take a snapshot of the mesh database and write it to a local sqlite to explore with the following command:

```bash
$ wmctl --insecure --server localhost:8443 snapshot --format sqlite --output data.sqlite
2023/06/13 23:33:14 INFO restoring db snapshot component=snapshots
2023/06/13 23:33:14 INFO db snapshot restore complete component=snapshots duration=38.352891ms

$ sqlite3 data.sqlite
SQLite version 3.42.0 2023-05-16 12:36:15
Enter ".help" for usage hints.
sqlite> .tables
groups                       node_private_rpc_addresses
leases                       node_public_rpc_addresses
mesh_state                   nodes
network_acls                 role_bindings
network_routes               roles
node_edges                   schema_version
node_private_raft_addresses  users
```
