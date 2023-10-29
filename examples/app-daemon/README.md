# App Daemon Example

This example shows running the `webmesh-node` as a daemon process for applications to interact with.
The API is served over gRPC and can be accessed by any language that supports gRPC.

The bindings for the API are defined in the [Webmesh API](https://github.com/webmeshproj/api) repository.
The schemas are published to the [Buf Schema Registry](https://buf.build/webmeshproj/api).

A pre-generated golang client interface can be found within the same repository [here](https://pkg.go.dev/github.com/webmeshproj/api/go/v1#AppDaemonClient).
A pre-generated Typescript interface is also available [here](https://webmeshproj.github.io/api/variables/app_connect.AppDaemon.html).

To start the daemon process, run the following command:

```bash
docker-compose up
```

This will start the daemon process with the following ports exposed.

| Port | Description |
| ---- | ----------- |
| 8080 | gRPC UI     |
| 8081 | gRPC API    |
