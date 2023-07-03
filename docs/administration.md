# Webmesh Administration

The Webmesh project is designed to be as simple as possible to administer.
Almost all settings can be determined automatically, and the rest can be configured via the [Admin API](https://github.com/webmeshproj/api/blob/main/proto/v1/admin.proto) or CLI by a node or user with the proper credentials.

Until better documentation is in place, this document shows the usage of the CLI utility included in this repository.

## Configuring the CLI

The CLI uses a Kubernetes-link configuration syntax with options for command line flags and environment variables.
For now the structure of the configuration can be found in the source [here](pkg/ctlcmd/config/config.go).
The default configuration is read from `~/.wmctl/config.yaml` and can be overridden with the `--config` flag or `WMCTL_CONFIG` environment variable.

An example configuration for a cluster using mTLS may look like this:

```yaml
apiVersion: webmesh.io/v1
kind: Config
clusters:
  - name: mesh-sample
    cluster:
      server: 172.19.0.2:8443
      tls-verify-chain-only: true
      certificate-authority-data: <redacted>
users:
  - name: mesh-sample-admin
    user:
      client-certificate-data: <redacted>
      client-key-data: <redacted>
contexts:
  - name: mesh-sample
    context:
      cluster: mesh-sample
      user: mesh-sample-admin
current-context: mesh-sample
```

Refer to the source for the full list of options.

## Reading Network State

```bash
$ wm get --help
Get resources from the mesh

Usage:
  wmctl get [command]

Available Commands:
  edges        Get edges from the mesh
  graph        Get the mesh graph in DOT format
  groups       Get groups from the mesh
  networkacls  Get network ACLs from the mesh
  nodes        Get nodes from the mesh
  rolebindings Get rolebindings from the mesh
  roles        Get roles from the mesh
  routes       Get routes from the mesh

Flags:
  -h, --help   help for get

Global Flags:
      --basic-auth-password func     The password for basic authentication
      --basic-auth-username func     The username for basic authentication
      --certificate-authority func   The path to the CA certificate for the cluster connection
      --client-certificate func      The path to the client certificate for the user
      --client-key func              The path to the client key for the user
  -c, --config string                Path to the CLI configuration file
      --context string               The name of the context to use (default "mesh-sample")
      --insecure                     Whether TLS should be disabled for the cluster connection
      --ldap-password func           The password for LDAP authentication
      --ldap-username func           The username for LDAP authentication
      --prefer-leader                Whether to prefer the leader node for the cluster connection
      --server string                The URL of the node to connect to (default "172.19.0.2:8443")
      --tls-skip-verify              Whether TLS verification should be skipped for the cluster connection

Use "wmctl get [command] --help" for more information about a command.
```

## Writing Configurations

```bash
$ wm put --help
Create or update resources in the mesh

Usage:
  wmctl put [command]

Available Commands:
  edges        Create or update an edge in the mesh
  groups       Create or update a group in the mesh
  networkacls  Create or update a networkacl in the mesh
  rolebindings Create or update a rolebindings in the mesh
  roles        Create or update a role with a single rule in the mesh
  routes       Create or update a route in the mesh

Flags:
  -h, --help   help for put

Global Flags:
      --basic-auth-password func     The password for basic authentication
      --basic-auth-username func     The username for basic authentication
      --certificate-authority func   The path to the CA certificate for the cluster connection
      --client-certificate func      The path to the client certificate for the user
      --client-key func              The path to the client key for the user
  -c, --config string                Path to the CLI configuration file
      --context string               The name of the context to use (default "mesh-sample")
      --insecure                     Whether TLS should be disabled for the cluster connection
      --ldap-password func           The password for LDAP authentication
      --ldap-username func           The username for LDAP authentication
      --prefer-leader                Whether to prefer the leader node for the cluster connection
      --server string                The URL of the node to connect to (default "172.19.0.2:8443")
      --tls-skip-verify              Whether TLS verification should be skipped for the cluster connection
```

Improved documentation is coming soon.
