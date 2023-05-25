-- name: CreateNode :one
INSERT INTO nodes (
    id,
    public_key,
    endpoint,
    network_ipv6,
    grpc_port,
    raft_port,
    wireguard_port,
    created_at,
    updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: UpdateNode :one
UPDATE nodes SET
    public_key = ?,
    endpoint = ?,
    network_ipv6 = ?,
    grpc_port = ?,
    raft_port = ?,
    wireguard_port = ?,
    updated_at = ?
WHERE id = ?
RETURNING *;

-- name: DeleteNode :exec
DELETE FROM nodes WHERE id = ?;

-- name: ListPublicRPCAddresses :many
SELECT node_id, CAST(address AS TEXT) FROM node_public_rpc_addresses;

-- name: GetNodePrivateRPCAddress :one
SELECT CAST(address AS TEXT) FROM node_private_rpc_addresses WHERE node_id = ?;

-- name: GetNodePublicRPCAddress :one
SELECT CAST(address AS TEXT) FROM node_public_rpc_addresses WHERE node_id = ?;

-- name: GetNodePrivateRPCAddresses :many
SELECT CAST(address AS TEXT) FROM node_private_rpc_addresses WHERE node_id <> ?;

-- name: GetNodePublicRPCAddresses :many
SELECT CAST(address AS TEXT) FROM node_public_rpc_addresses WHERE node_id <> ?;

-- name: GetNode :one
SELECT
    nodes.id AS id,
    nodes.public_key AS public_key,
    nodes.endpoint AS endpoint,
    nodes.grpc_port AS grpc_port,
    nodes.raft_port AS raft_port,
    nodes.wireguard_port AS wireguard_port,
    nodes.network_ipv6 AS network_ipv6,
    COALESCE(leases.ipv4, '') AS private_address_v4,
    nodes.updated_at AS updated_at,
    nodes.created_at AS created_at
FROM nodes 
LEFT OUTER JOIN leases ON nodes.id = leases.node_id
WHERE nodes.id = ?;

-- name: ListNodes :many
SELECT
    nodes.id AS id,
    nodes.public_key AS public_key,
    nodes.endpoint AS endpoint,
    nodes.grpc_port AS grpc_port,
    nodes.raft_port AS raft_port,
    nodes.wireguard_port AS wireguard_port,
    nodes.network_ipv6 AS network_ipv6,
    COALESCE(leases.ipv4, '') AS private_address_v4,
    nodes.updated_at AS updated_at,
    nodes.created_at AS created_at
FROM nodes 
LEFT OUTER JOIN leases ON nodes.id = leases.node_id;

-- name: ListNodePeers :many
SELECT
    nodes.id AS id,
    nodes.public_key AS public_key,
    nodes.endpoint AS endpoint,
    nodes.grpc_port AS grpc_port,
    nodes.raft_port AS raft_port,
    nodes.wireguard_port AS wireguard_port,
    nodes.network_ipv6 AS network_ipv6,
    nodes.updated_at AS updated_at,
    nodes.created_at AS created_at,
    COALESCE(leases.ipv4, '') AS private_address_v4
FROM nodes
LEFT OUTER JOIN leases ON nodes.id = leases.node_id
WHERE nodes.id <> ?;

-- name: GetNodePeer :one
SELECT
    nodes.id AS id,
    nodes.public_key AS public_key,
    nodes.endpoint AS endpoint,
    nodes.grpc_port AS grpc_port,
    nodes.raft_port AS raft_port,
    nodes.wireguard_port AS wireguard_port,
    nodes.network_ipv6 AS network_ipv6,
    COALESCE(leases.ipv4, '') AS private_address_v4
FROM nodes
LEFT OUTER JOIN leases ON nodes.id = leases.node_id
WHERE nodes.id = ?;