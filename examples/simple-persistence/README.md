# Simple Example with Persistence

This example just has a single bootstrap server and a single join node.
None of the optional services are enabled so very limited functionality is available.
This is just like the [simple example](../simple/README.md) except that it uses data persistence to the local disk.

## Running

You can run the example with the following command:

```bash
docker-compose up
```

To shutdown the example, press `Ctrl+C` and then run:

```bash
docker-compose down -v
```

There isn't much else to do with this example since none of the APIs are enabled.
But you can still exec into them to test connectivity and such.
