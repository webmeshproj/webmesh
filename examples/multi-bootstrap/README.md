# Multiple Bootstrap Node Cluster

This example has three nodes that all start a new cluster as voters.
It also enables several of the optional APIs so that you can see how they work.

## Running

You can run the example with the following command:

```bash
docker-compose up
```

Stop it with:

```
docker-compose down -v
```

## Using

You can play with the various APIs using the `wmctl` CLI tool.

```bash
# List the nodes in the mesh
$ wmctl --insecure --server localhost:8443 get nodes
[
  {
    "id":  "bootstrap-node-2",
    "primaryEndpoint":  "10.1.0.2",
    "wireguardEndpoints":  [
      "10.1.0.2:51820"
    ],
    "raftPort":  9443,
    "grpcPort":  8443,
    "publicKey":  "G1d5euMxkKTUSPgqztq5f0rhKTSomUMeorZlFodmDEI=",
    "privateIpv4":  "10.10.10.1/24",
    "privateIpv6":  "fd88:b2e2:e646:a552::/64",
    "updatedAt":  "2023-06-12T17:52:47.735916064Z",
    "createdAt":  "2023-06-12T17:52:47.735916014Z",
    "clusterStatus":  "CLUSTER_LEADER"
  },
  {
    "id":  "bootstrap-node-1",
    "primaryEndpoint":  "10.1.0.1",
    "wireguardEndpoints":  [
      "10.1.0.1:51820"
    ],
    "raftPort":  9443,
    "grpcPort":  8443,
    "publicKey":  "T1grhbfPpayzkVRy3WSUZX+R6dpLqVJ2qHoe4RzBegs=",
    "privateIpv4":  "10.10.10.2/24",
    "privateIpv6":  "fd88:b2e2:e646:4465::/64",
    "updatedAt":  "2023-06-12T17:52:50.455848009Z",
    "createdAt":  "2023-06-12T17:52:47.765849195Z",
    "clusterStatus":  "CLUSTER_VOTER"
  },
  {
    "id":  "bootstrap-node-3",
    "primaryEndpoint":  "10.1.0.3",
    "wireguardEndpoints":  [
      "10.1.0.3:51820"
    ],
    "raftPort":  9443,
    "grpcPort":  8443,
    "publicKey":  "rgcbAqXQEhEvR57Y/jj+0XSQh1W0FdW0o6wHNHq7PRY=",
    "privateIpv4":  "10.10.10.3/24",
    "privateIpv6":  "fd88:b2e2:e646:7d5c::/64",
    "updatedAt":  "2023-06-12T17:52:50.503904235Z",
    "createdAt":  "2023-06-12T17:52:47.832976431Z",
    "clusterStatus":  "CLUSTER_VOTER"
  }
]

# Get a DOT graph of the cluster
$ wmctl --insecure --server localhost:8443 get graph
strict graph {


        "bootstrap-node-1" [  weight=0 ];

        "bootstrap-node-1" -- "bootstrap-node-2" [  weight=99 ];

        "bootstrap-node-1" -- "bootstrap-node-3" [  weight=99 ];

        "bootstrap-node-2" [  weight=0 ];

        "bootstrap-node-2" -- "bootstrap-node-3" [  weight=99 ];

        "bootstrap-node-2" -- "bootstrap-node-1" [  weight=99 ];

        "bootstrap-node-3" [  weight=0 ];

        "bootstrap-node-3" -- "bootstrap-node-1" [  weight=99 ];

        "bootstrap-node-3" -- "bootstrap-node-2" [  weight=99 ];

}

# Interact with the MeshDNS server
$ dig @localhost -p 5354 leader

; <<>> DiG 9.18.15 <<>> @localhost -p 5354 leader
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1656
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 1, ADDITIONAL: 1
;; WARNING: Message has 162 extra bytes at end

;; QUESTION SECTION:
;leader.                                IN      A

;; ANSWER SECTION:
leader.webmesh.internal. 1      IN      CNAME   bootstrap-node-2.webmesh.internal.
bootstrap-node-2.webmesh.internal. 1 IN A       10.10.10.1

;; Query time: 1 msec
;; SERVER: 127.0.0.1#5354(localhost) (UDP)
;; WHEN: Mon Jun 12 20:54:26 IDT 2023
;; MSG SIZE  rcvd: 268


$ dig @localhost -p 5354 voters

; <<>> DiG 9.18.15 <<>> @localhost -p 5354 voters
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 18938
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 6, AUTHORITY: 1, ADDITIONAL: 3
;; WARNING: Message has 391 extra bytes at end

;; QUESTION SECTION:
;voters.                                IN      A

;; ANSWER SECTION:
voters.webmesh.internal. 1      IN      CNAME   bootstrap-node-2.webmesh.internal.
voters.webmesh.internal. 1      IN      CNAME   bootstrap-node-1.webmesh.internal.
voters.webmesh.internal. 1      IN      CNAME   bootstrap-node-3.webmesh.internal.
bootstrap-node-2.webmesh.internal. 1 IN A       10.10.10.1
bootstrap-node-1.webmesh.internal. 1 IN A       10.10.10.2
bootstrap-node-3.webmesh.internal. 1 IN A       10.10.10.3

;; Query time: 1 msec
;; SERVER: 127.0.0.1#5354(localhost) (UDP)
;; WHEN: Mon Jun 12 20:54:36 IDT 2023
;; MSG SIZE  rcvd: 591

```

You can also try out the TURN server with the `wmctl port-forward` command.
This will receive more documentation later.
