-- +goose Up

-- Mesh wide configurations are stored here, but these should be moved.
CREATE TABLE mesh_state (
    key   TEXT NOT NULL PRIMARY KEY,
    value TEXT NOT NULL
);

-- Tracks node lifecycle and configuration.
CREATE TABLE nodes (
    id                TEXT NOT NULL PRIMARY KEY,
    public_key        TEXT,
    raft_port         INTEGER NOT NULL DEFAULT 9444,
    grpc_port         INTEGER NOT NULL DEFAULT 8443,
    wireguard_port    INTEGER NOT NULL DEFAULT 51820,
    public_endpoint   TEXT UNIQUE,
    network_ipv6      TEXT UNIQUE,
    created_at        TIMESTAMP NOT NULL,
    updated_at        TIMESTAMP NOT NULL
);

-- Tracks IPv4 leases for nodes.
CREATE TABLE leases (
    node_id     TEXT NOT NULL UNIQUE REFERENCES nodes (id) ON DELETE CASCADE,
    ipv4        TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMP NOT NULL
);

-- Raft ACLs determine who can vote in elections.
CREATE TABLE raft_acls (
    name        TEXT NOT NULL PRIMARY KEY,
    nodes       TEXT NOT NULL,
    action      INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMP NOT NULL,
    updated_at  TIMESTAMP NOT NULL
);

-- Tracks edges between nodes for the mesh graph.
CREATE TABLE node_edges (
    src_node_id  TEXT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    dst_node_id  TEXT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    weight       INTEGER NOT NULL DEFAULT 1,
    attrs        TEXT
);

-- Views for more convenient querying.

CREATE VIEW node_private_rpc_addresses AS
SELECT
    nodes.id as node_id,
    SUBSTR(
        COALESCE(leases.ipv4, nodes.network_ipv6, ''),
        0,
        INSTR(COALESCE(leases.ipv4, nodes.network_ipv6, ''), '/')
    )
    || ':'
    || CAST(nodes.grpc_port AS TEXT) AS address
FROM nodes 
LEFT OUTER JOIN leases ON nodes.id = leases.node_id;

CREATE VIEW node_public_rpc_addresses AS
SELECT
    nodes.id as node_id,
    nodes.public_endpoint
    || ':'
    || CAST(nodes.grpc_port AS TEXT) AS address
FROM nodes WHERE nodes.public_endpoint IS NOT NULL;

CREATE VIEW node_private_raft_addresses AS
SELECT
    nodes.id as node_id,
    SUBSTR(
        COALESCE(leases.ipv4, nodes.network_ipv6, ''),
        0,
        INSTR(COALESCE(leases.ipv4, nodes.network_ipv6, ''), '/')
    )
    || ':'
    || CAST(nodes.raft_port AS TEXT) AS address
FROM nodes
LEFT OUTER JOIN leases ON nodes.id = leases.node_id;

CREATE VIEW node_public_raft_addresses AS
SELECT
    nodes.id as node_id,
    nodes.public_endpoint
    || ':'
    || CAST(nodes.raft_port AS TEXT) AS address
FROM nodes WHERE nodes.public_endpoint IS NOT NULL;

-- +goose Down

DROP TABLE node_edges;
DROP TABLE raft_acls;
DROP TABLE leases;
DROP TABLE nodes;
DROP TABLE mesh_state;

DROP VIEW node_private_rpc_addresses;
DROP VIEW node_public_rpc_addresses;
DROP VIEW node_private_raft_addresses;
DROP VIEW node_public_raft_addresses;
