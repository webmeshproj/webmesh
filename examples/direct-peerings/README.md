# Direct Peerings over ICE

This example displays using a node as a TURN server to faciliate direct peerings between nodess behind NATs.
Under normal conditions, peerings only happen between nodes that can directly reach each other.
Nodes can be configured to connect directly via the admin interface through manual edge creation or via the `--mesh.direct-peers` flag (assuming the node has permission to create data channels).
