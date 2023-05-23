-- +goose Up

-- Tracks mesh state, such as indices and the current epoch.
-- Mesh wide configurations are also stored here, but these should be moved.
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
    endpoint          TEXT UNIQUE,
    network_ipv6      TEXT UNIQUE,
    allowed_ips       TEXT,
    available_zones   TEXT,
    last_heartbeat_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Tracks BGP ASNs for nodes.
CREATE TABLE asns (
    asn         INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT CHECK (asn > 0 AND asn < 65536),
    node_id     TEXT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Tracks IPv4 leases for nodes.
CREATE TABLE leases (
    node_id     TEXT NOT NULL UNIQUE REFERENCES nodes (id) ON DELETE CASCADE,
    ipv4        TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  TIMESTAMP NOT NULL
);

-- A table for node-local storage of arbitrary key/value pairs
-- Data in this table is not replicated to other nodes. This is
-- a stop-gap solution for data that should otherwise be handled
-- better.
CREATE TABLE node_local (
    key         TEXT NOT NULL PRIMARY KEY,
    value       TEXT NOT NULL
);

-- +goose Down

DROP TABLE leases;
DROP TABLE nodes;
DROP TABLE asns;
DROP TABLE mesh_state;
DROP TABLE node_local;
