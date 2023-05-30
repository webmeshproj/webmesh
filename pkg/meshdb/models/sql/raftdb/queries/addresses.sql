-- name: ListPublicRPCAddresses :many
SELECT
    node_id AS node_id,
    CAST(address AS TEXT) AS address
FROM node_public_rpc_addresses;

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

-- name: GetNodePrivateRPCAddress :one
SELECT
    CAST(address AS TEXT) AS address
FROM node_private_rpc_addresses
WHERE node_id = ?;
