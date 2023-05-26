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
    primary_endpoint  TEXT UNIQUE,
    endpoints         TEXT UNIQUE,
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

-- Raft ACLs determine who can join the cluster as what.
CREATE TABLE raft_acls (
    name        TEXT NOT NULL PRIMARY KEY,
    nodes       TEXT NOT NULL,
    voter       BOOLEAN NOT NULL DEFAULT FALSE,
    observer    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMP NOT NULL,
    updated_at  TIMESTAMP NOT NULL
);

-- Network ACLs determine traffic policies for non-voting nodes.
-- Voting nodes have to be able to communicate with each other.
-- In the future nodes should handle leaving tunnels for raft 
-- traffic open.
CREATE TABLE network_acls (
    name        TEXT NOT NULL PRIMARY KEY,
    proto       TEXT NOT NULL,
    src_cidrs   TEXT,
    dst_cidrs   TEXT,
    src_nodes   TEXT,
    dst_nodes   TEXT,
    action      TEXT NOT NULL,
    priority    INTEGER NOT NULL,
    created_at  TIMESTAMP NOT NULL,
    updated_at  TIMESTAMP NOT NULL
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
    nodes.primary_endpoint
    || ':'
    || CAST(nodes.grpc_port AS TEXT) AS address
FROM nodes WHERE nodes.primary_endpoint IS NOT NULL;

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
    nodes.primary_endpoint
    || ':'
    || CAST(nodes.raft_port AS TEXT) AS address
FROM nodes WHERE nodes.primary_endpoint IS NOT NULL;

CREATE VIEW node_primary_wireguard_endpoints AS
SELECT
    nodes.id AS node_id,
    nodes.primary_endpoint
    || ':'
    || CAST(nodes.wireguard_port AS TEXT) AS address
FROM nodes WHERE nodes.primary_endpoint IS NOT NULL;

CREATE VIEW node_all_wireguard_endpoints AS
SELECT
    nodes.id AS node_id,
    nodes.primary_endpoint
    || ','
    || COALESCE(nodes.endpoints || ',', '') AS endpoints,
    nodes.wireguard_port AS port
FROM nodes
WHERE nodes.primary_endpoint IS NOT NULL;

-- +goose Down

DROP TABLE leases;
DROP TABLE nodes;
DROP TABLE asns;
DROP TABLE mesh_state;
DROP VIEW node_private_rpc_addresses;
DROP VIEW node_public_rpc_addresses;
DROP VIEW node_private_raft_addresses;
DROP VIEW node_public_raft_addresses;
DROP VIEW node_primary_wireguard_endpoints;
DROP VIEW node_all_wireguard_endpoints;
