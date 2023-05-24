-- +goose Up

-- Tables for node-local storage of arbitrary key/value pairs
-- and other data. This schema is not replicated to other nodes. 
-- This is a stop-gap solution for data that should otherwise be 
-- handled better.

CREATE TABLE node_local_kv (
    key         TEXT NOT NULL PRIMARY KEY,
    value       TEXT NOT NULL
);

CREATE TABLE wireguard_key (
    id          INTEGER NOT NULL PRIMARY KEY, -- Always 1
    private_key TEXT NOT NULL,
    expires_at  TIMESTAMP
);

CREATE TABLE raft_index (
    id          INTEGER NOT NULL PRIMARY KEY, -- Always 1
    term        INTEGER NOT NULL,
    index       INTEGER NOT NULL
);

-- +goose Down

DROP TABLE node_local_kv;
DROP TABLE wireguard_key;
DROP TABLE raft_index;
