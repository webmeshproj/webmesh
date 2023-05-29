-- name: ListPublicRPCAddresses :many
SELECT
    node_id AS node_id,
    CAST(address AS TEXT) AS address
FROM node_public_rpc_addresses;

-- name: ListPublicWireguardEndpoints :many
SELECT
    nodes.id AS node_id,
    CAST(nodes.primary_endpoint
    || ':'
    || CAST(nodes.wireguard_port AS TEXT) AS TEXT) AS endpoint
FROM nodes WHERE nodes.primary_endpoint IS NOT NULL;

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
