# Direct Peerings over Libp2p

This example shows a single public bootstrap node and two other nodes that form direct peerings with each other over libp2p relays.
This is similar to the [ICE Peerings](../ice-peerings/) example, but uses libp2p relays instead of a TURN server.

Nodes that wish to communicate directly over libp2p share a rendezvous point where they will agree to meet.
This rendezvous point is a string on the Kadmelia DHT.
Once the circuit relay is created, it is used to establish a WireGuard tunnel between the two nodes.

For more information, see the [configuration reference](https://webmeshproj.github.io/documentation/configuration/).

## Running the example

This example uses the `--mesh.libp2p-peers` flag to configure the nodes to connect directly via libp2p.
The `--libp2p.ice-peers` flag takes a map of peer IDs to rendezvous strings.

You can run the example with:

```bash
docker-compose up
```

To shutdown the example, press `Ctrl+C` and then run:

```bash
docker-compose down -v
```
