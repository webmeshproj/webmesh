# Local Storage Plugin

This example is just like the [simple](../simple/) example, but it also enables the `localstore` plugin.
Under regular circumstances, the database of the mesh state is kept in memory with snapshots periodically written to disk.
Snapshots can also be forced with the `wmctl snapshot` command.

The `localstore` plugin allows the mesh state to be written to a local sqlite database alongside the in-memory one.
This allows you to explore the mesh state with a sqlite client, or to use the database as an extra backup for the in-memory state.

## Running

You can run the example with the following command:

```bash
docker-compose up
```

Stop it with:

```bash
docker-compose down -v
```

To peek at the database, you can use the sqlite client inside the bootstrap-node container.

```bash
$ docker-compose exec bootstrap-node sh

/> ls /data/localstore/
webmesh.db

/> sqlite3 /data/localstore/webmesh.db
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.

sqlite> .tables
groups                       node_private_rpc_addresses
leases                       node_public_rpc_addresses
mesh_state                   nodes
network_acls                 role_bindings
network_routes               roles
node_edges                   schema_version
node_private_raft_addresses  users
sqlite>
```
