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
SELECT node_id, CAST(address AS TEXT) AS address FROM node_public_rpc_addresses;

-- name: ListPublicWireguardEndpoints :many
SELECT node_id, CAST(address AS TEXT) AS address FROM node_public_wireguard_endpoints;

-- name: GetNodePrivateRPCAddress :one
SELECT CAST(address AS TEXT) AS address FROM node_private_rpc_addresses WHERE node_id = ?;

-- name: GetNodePublicRPCAddress :one
SELECT CAST(address AS TEXT) AS address FROM node_public_rpc_addresses WHERE node_id = ?;

-- name: GetNodePrivateRPCAddresses :many
SELECT CAST(address AS TEXT) AS address FROM node_private_rpc_addresses WHERE node_id <> ?;

-- name: GetNodePublicRPCAddresses :many
SELECT CAST(address AS TEXT) AS address FROM node_public_rpc_addresses WHERE node_id <> ?;
