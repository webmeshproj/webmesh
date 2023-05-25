-- name: SetULAPrefix :exec
INSERT into mesh_state (key, value) VALUES ('ULAPrefix', ?)
ON CONFLICT (key) DO UPDATE SET value = excluded.value;

-- name: GetULAPrefix :one
SELECT value FROM mesh_state WHERE key = 'ULAPrefix';

-- name: SetIPv4Prefix :exec
INSERT into mesh_state (key, value) VALUES ('IPv4Prefix', ?)
ON CONFLICT (key) DO UPDATE SET value = excluded.value;

-- name: GetIPv4Prefix :one
SELECT value FROM mesh_state WHERE key = 'IPv4Prefix';

-- name: ListPublicRPCAddresses :many
SELECT
    node_id AS node_id,
    CAST(address AS TEXT) AS address
FROM node_public_rpc_addresses;

-- name: ListPublicWireguardEndpoints :many
SELECT
    node_id AS node_id,
    CAST(endpoints AS TEXT) AS endpoints,
    CAST(port AS INTEGER) AS port
FROM node_all_wireguard_endpoints;

-- name: GetNodePrivateRPCAddress :one
SELECT
    CAST(address AS TEXT) AS address
FROM node_private_rpc_addresses
WHERE node_id = ?;

-- name: GetNodePublicRPCAddress :one
SELECT
    CAST(address AS TEXT) AS address
FROM node_public_rpc_addresses
WHERE node_id = ?;

-- name: GetPeerPrivateRPCAddresses :many
SELECT
    CAST(address AS TEXT) AS address
FROM node_private_rpc_addresses
WHERE node_id <> ?;

-- name: GetPeerPublicRPCAddresses :many
SELECT
    CAST(address AS TEXT) AS address
FROM node_public_rpc_addresses
WHERE node_id <> ?;
