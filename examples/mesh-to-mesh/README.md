# Mesh to Mesh

This example shows bridging two independent Webmesh clusters together.
The way we accomplish this is with a "bridge node".
This node is a member of both clusters and acts as a bridge between them, forwarding traffic across the interfaces as needed.
The node may also expose a MeshDNS server to provide forward name resolution between the meshes.

## Example

The architecture of this example looks like this:

```

+------------------+      +------------------+      +------------------+
|                  |      |                  |      |                  |
|  Mesh 1          | <--> |  Bridge Node     | <--> |  Mesh 2          |
|                  |      |                  |      |                  |
+------------------+      +------------------+      +------------------+

```

Where "Mesh 1" and "Mesh 2" are two independent Webmesh clusters that can be branched off into their own networks.
The "Bridge Node" is a member of both clusters and acts as a bridge between them.
It also exposes a MeshDNS server to provide forward name resolution between the meshes.
This setup currently only supports IPv6, but IPv4 support via a NAT64 implementation or similar is planned.

The `docker-compose.yaml` shows how to set up this example along with documentation on what the options mean.

To start it run the following command:

```bash
docker-compose up
```

There is a small chance the first attempt will fail (largely due to starting everything at once).
If that happens, just restart it and it should work.

```bash
docker-compose down -v
docker-compose up
```

With all the nodes running you should be able to ping between the two meshes.

```bash
# Ping site-2-node from site-1-node
$ docker-compose exec site-1-node ping6 site-2-node.site-2.internal

PING site-2-node.site-2.internal (fdff:2b3e:9e5d:fe40::): 56 data bytes
64 bytes from fdff:2b3e:9e5d:fe40::: seq=0 ttl=63 time=0.398 ms
64 bytes from fdff:2b3e:9e5d:fe40::: seq=1 ttl=63 time=0.664 ms
64 bytes from fdff:2b3e:9e5d:fe40::: seq=2 ttl=63 time=0.579 ms

# Ping site-1-node from site-2-node
$ docker-compose exec site-2-node ping6 site-1-node.site-1.internal

PING site-1-node.site-1.internal (fdd9:459:42d:f6f7::): 56 data bytes
64 bytes from fdd9:459:42d:f6f7::: seq=0 ttl=63 time=0.649 ms
64 bytes from fdd9:459:42d:f6f7::: seq=1 ttl=63 time=0.506 ms
64 bytes from fdd9:459:42d:f6f7::: seq=2 ttl=63 time=0.530 ms
```
