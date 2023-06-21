-- name: ListPublicRPCAddresses :many
SELECT
    node_id AS node_id,
    CAST(address AS TEXT) AS address
FROM node_public_rpc_addresses;

-- name: ListPeerPublicRPCAddresses :many
SELECT
    node_id AS node_id,
    CAST(address AS TEXT) AS address
FROM node_public_rpc_addresses
WHERE node_id <> ?;

-- name: ListPrivateRPCAddresses :many
SELECT
    node_id AS node_id,
    CAST(address AS TEXT) AS address
FROM node_private_rpc_addresses;

-- name: ListPeerPrivateRPCAddresses :many
SELECT
    node_id AS node_id,
    CAST(address AS TEXT) AS address
FROM node_private_rpc_addresses
WHERE node_id <> ?;

-- name: GetNodePublicRPCAddress :one
SELECT
    CAST(address AS TEXT) AS address
FROM node_public_rpc_addresses
WHERE node_id = ?;

-- name: GetNodePrivateRPCAddress :one
SELECT
    CAST(address AS TEXT) AS address
FROM node_private_rpc_addresses
WHERE node_id = ?;
