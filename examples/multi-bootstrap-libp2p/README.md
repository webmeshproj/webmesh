# Bootstrap over Libp2p

This example has three nodes that all start a new cluster as voters.
They perform their initial leader election over libp2p.
All sides of the connection share a rendezvous string and a pre-shared key that is used to sign and verify election results and votes.

## Running

You can run the example with the following command:

```bash
# Generate a random rendezvous string and pre-shared key
export PSK=$(echo "$RANDOM" | md5sum | cut -d ' ' -f1)
export RENDEZVOUS=$(echo "$RANDOM" | md5sum | cut -d ' ' -f1)
# Start the nodes - this can take upwards of 30-60 seconds
# depending on the speed of the discovery mechanism
docker-compose up
```

To shutdown the example, press `Ctrl+C` and then run:

```bash
docker-compose down -v
```
