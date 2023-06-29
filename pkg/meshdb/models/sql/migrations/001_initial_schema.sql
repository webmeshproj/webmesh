-- +goose Up

-- Mesh wide configurations are stored here, but these should be moved.
CREATE TABLE mesh_state (
    key   TEXT NOT NULL PRIMARY KEY,
    value TEXT NOT NULL
);

-- Tracks node lifecycle and configuration.
CREATE TABLE nodes (
    id                    TEXT NOT NULL PRIMARY KEY,
    public_key            TEXT UNIQUE,
    raft_port             INTEGER NOT NULL DEFAULT 9444,
    grpc_port             INTEGER NOT NULL DEFAULT 8443,
    primary_endpoint      TEXT,
    wireguard_endpoints   TEXT,
    zone_awareness_id     TEXT,
    network_ipv6          TEXT UNIQUE,
    created_at            TIMESTAMP NOT NULL,
    updated_at            TIMESTAMP NOT NULL
);

-- Tracks edges between nodes for the mesh graph.
CREATE TABLE node_edges (
    src_node_id  TEXT NOT NULL,
    dst_node_id  TEXT NOT NULL,
    weight       INTEGER NOT NULL DEFAULT 1,
    attrs        TEXT
);

-- Tracks IPv4 leases for nodes.
CREATE TABLE leases (
    node_id     TEXT NOT NULL UNIQUE REFERENCES nodes (id) ON DELETE CASCADE,
    ipv4        TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMP NOT NULL
);

-- Tracks users. Users are simply certificates signed by the CA that are not
-- necessarily associated with a node. It's possible the two concepts should
-- be merged. However, for now, there may be use cases where a user is purely
-- for administrative purposes and never actually joins as a node.
CREATE TABLE users (
    name         TEXT NOT NULL PRIMARY KEY,
    created_at   TIMESTAMP NOT NULL,
    updated_at   TIMESTAMP NOT NULL
);

-- Tracks groups. Groups are collections of users and/or nodes.
CREATE TABLE groups (
    name         TEXT NOT NULL PRIMARY KEY,
    users        TEXT,
    nodes        TEXT,
    created_at   TIMESTAMP NOT NULL,
    updated_at   TIMESTAMP NOT NULL
);

-- Tracks roles. Roles are collections of rules that can be bound to users and nodes
CREATE TABLE roles (
    name         TEXT NOT NULL PRIMARY KEY,
    rules_json   TEXT NOT NULL,
    created_at   TIMESTAMP NOT NULL,
    updated_at   TIMESTAMP NOT NULL
);

-- Tracks role bindings. Role bindings are the association of a role to users and/or nodes.
CREATE TABLE role_bindings (
    name         TEXT NOT NULL PRIMARY KEY,
    role_name    TEXT NOT NULL REFERENCES roles (name) ON DELETE CASCADE,
    node_ids     TEXT,
    user_names   TEXT,
    group_names  TEXT,
    created_at   TIMESTAMP NOT NULL,
    updated_at   TIMESTAMP NOT NULL
);

-- Network ACLs determine who can communicate with whom.
CREATE TABLE network_acls (
    name         TEXT NOT NULL PRIMARY KEY,
    priority     INTEGER NOT NULL DEFAULT 0,
    action       INTEGER NOT NULL DEFAULT 0,
    src_node_ids TEXT,
    dst_node_ids TEXT,
    src_cidrs    TEXT,
    dst_cidrs    TEXT,
    protocols    TEXT,
    ports        TEXT,
    created_at   TIMESTAMP NOT NULL,
    updated_at   TIMESTAMP NOT NULL
);

-- Network Routes are non-mesh routes advertised by nodes.
CREATE TABLE network_routes (
    name       TEXT NOT NULL PRIMARY KEY,
    node       TEXT NOT NULL,
    dst_cidrs  TEXT NOT NULL,
    next_hop   TEXT,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

-- +goose Down

DROP TABLE network_routes;
DROP TABLE network_acls;
DROP TABLE role_bindings;
DROP TABLE roles;
DROP TABLE groups;
DROP TABLE users;
DROP TABLE leases;
DROP TABLE node_edges;
DROP TABLE nodes;
DROP TABLE mesh_state;
