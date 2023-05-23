-- +goose Up

-- A table for node-local storage of arbitrary key/value pairs
-- Data in this table is not replicated to other nodes. This is
-- a stop-gap solution for data that should otherwise be handled
-- better.
CREATE TABLE node_local (
    key         TEXT NOT NULL PRIMARY KEY,
    value       TEXT NOT NULL
);

-- +goose Down

DROP TABLE node_local;
