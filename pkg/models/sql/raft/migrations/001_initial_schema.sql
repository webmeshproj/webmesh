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
    endpoint          TEXT UNIQUE,
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
    nodes.endpoint
    || ':'
    || CAST(nodes.grpc_port AS TEXT) AS address
FROM nodes WHERE nodes.endpoint IS NOT NULL;

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
    nodes.endpoint
    || ':'
    || CAST(nodes.raft_port AS TEXT) AS address
FROM nodes WHERE nodes.endpoint IS NOT NULL;

CREATE VIEW node_public_wireguard_endpoints AS
SELECT
    nodes.id as node_id,
    nodes.endpoint
    || ':'
    || CAST(nodes.wireguard_port AS TEXT) AS address
FROM nodes WHERE nodes.endpoint IS NOT NULL;

-- +goose Down

DROP TABLE leases;
DROP TABLE nodes;
DROP TABLE asns;
DROP TABLE mesh_state;
