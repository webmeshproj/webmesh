# Direct Peerings over ICE

This example displays using a node as a TURN server to facilitate direct peerings between nodes behind NATs or otherwise not directly accessible.
Under normal conditions, peerings only happen between nodes that can directly reach each other.
Nodes can be configured to connect directly via the admin interface through manual edge creation or via the `--mesh.direct-peers` flag (assuming the node has permission to create data channels).

Each node can optionally expose one or both of the WebRTC API or a TURN server.
The WebRTC API is used to help facilitate ICE negotiation between nodes.
The TURN server can be used to relay traffic between nodes that cannot directly reach each other.
You can also use external TURN servers.

For more information, see the [configuration reference](https://webmeshproj.github.io/documentation/configuration/).
