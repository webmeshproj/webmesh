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
    endpoint          TEXT UNIQUE,
    network_ipv6      TEXT UNIQUE,
    allowed_ips       TEXT,
    available_zones   TEXT,
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
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
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE VIEW node_rpc_addresses AS
SELECT
    nodes.id as node_id,
    COALESCE(leases.ipv4, nodes.network_ipv6, '') AS address,
    nodes.grpc_port AS port
FROM nodes 
LEFT OUTER JOIN leases ON nodes.id = leases.node_id;

-- +goose Down

DROP TABLE leases;
DROP TABLE nodes;
DROP TABLE asns;
DROP TABLE mesh_state;
