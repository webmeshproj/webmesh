# Remote Server Plugin

This example is just like the [simple](../simple/) example, but it registers an external server as a plugin.
The example plugin implements the Watch RPC, which allows the plugin to be notified of changes to the mesh state.

## Running

You can run the example with the following command:

```bash
# Start the plugin server
go run ./main.go -listen-address :8081

# In another terminal, start the nodes
docker-compose up
```

The plugin will be notified when the `join-node` is added to the mesh state.
