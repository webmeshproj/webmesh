# Direct Peerings over ICE

This example displays using a node as a TURN server to facilitate direct peerings between nodes behind NATs or otherwise not directly accessible.
Under normal conditions, peerings only happen between nodes that can directly reach each other.
Nodes can be configured to connect directly via the admin interface through manual edge creation or via the `--mesh.ice-peers` flag (assuming the node has permission to create data channels).

Each node can optionally expose one or both of the WebRTC API or a TURN server.
The WebRTC API is used to help facilitate ICE negotiation between nodes.
The TURN server can be used to relay traffic between nodes that cannot directly reach each other.
You can also use external TURN servers.

Once the ICE tunnel has been established, it is used to establish a WireGuard tunnel between the two nodes.

For more information, see the [configuration reference](https://webmeshproj.github.io/documentation/configuration/).

## Running the example

This example uses the `--mesh.ice-peers` flag to configure the nodes to connect directly via ICE.
The `--mesh.ice-peers` flag takes a comma-separated list of peer IDs and ICE URLs.

You can run the example with:

```bash
docker-compose up
```

To shutdown the example, press `Ctrl+C` and then run:

```bash
docker-compose down -v
```
