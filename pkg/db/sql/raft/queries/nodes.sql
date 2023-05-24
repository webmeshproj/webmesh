-- name: CreateNode :one
INSERT INTO nodes (
    id,
    public_key,
    endpoint,
    available_zones,
    allowed_ips,
    network_ipv6,
    grpc_port,
    raft_port,
    created_at,
    updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: UpdateNode :one
UPDATE nodes SET
    public_key = ?,
    endpoint = ?,
    available_zones = ?,
    allowed_ips = ?,
    network_ipv6 = ?,
    grpc_port = ?,
    raft_port = ?,
    updated_at = ?
WHERE id = ?
RETURNING *;

-- name: GetNodePrivateRPCAddress :one
SELECT CAST(address AS TEXT) FROM node_rpc_addresses WHERE node_id = ?;

-- name: GetNodePublicRPCAddress :one
SELECT CAST(address AS TEXT) FROM node_public_rpc_addresses WHERE node_id = ?;

-- name: GetPeerPrivateRPCAddresses :many
SELECT CAST(address AS TEXT) FROM node_rpc_addresses WHERE node_id <> ?;

-- name: GetPeerPublicRPCAddresses :many
SELECT CAST(address AS TEXT) FROM node_public_rpc_addresses WHERE node_id <> ?;

-- name: GetNode :one
SELECT
    nodes.id AS id,
    nodes.public_key AS public_key,
    nodes.endpoint AS endpoint,
    nodes.allowed_ips AS allowed_ips,
    nodes.available_zones AS available_zones,
    nodes.grpc_port AS grpc_port,
    nodes.raft_port AS raft_port,
    nodes.network_ipv6 AS network_ipv6,
    COALESCE(asns.asn, 0) AS asn,
    COALESCE(leases.ipv4, '') AS private_address_v4,
    nodes.updated_at AS updated_at,
    nodes.created_at AS created_at
FROM nodes 
LEFT OUTER JOIN leases ON nodes.id = leases.node_id
LEFT OUTER JOIN asns ON nodes.id = asns.node_id
WHERE nodes.id = ?;

-- name: ListNodes :many
SELECT
    nodes.id AS id,
    nodes.public_key AS public_key,
    nodes.endpoint AS endpoint,
    nodes.allowed_ips AS allowed_ips,
    nodes.available_zones AS available_zones,
    nodes.grpc_port AS grpc_port,
    nodes.raft_port AS raft_port,
    nodes.network_ipv6 AS network_ipv6,
    COALESCE(asns.asn, 0) AS asn,
    COALESCE(leases.ipv4, '') AS private_address_v4,
    nodes.updated_at AS updated_at,
    nodes.created_at AS created_at
FROM nodes 
LEFT OUTER JOIN leases ON nodes.id = leases.node_id
LEFT OUTER JOIN asns ON nodes.id = asns.node_id;

-- name: AssignNodeASN :one
INSERT INTO asns (node_id, created_at) VALUES (?, ?) RETURNING *;

-- name: UnassignNodeASN :exec
DELETE FROM asns WHERE node_id = ?;

-- name: ListNodePeers :many
SELECT
    nodes.id AS id,
    nodes.public_key AS public_key,
    COALESCE(asns.asn, 0) AS asn,
    nodes.endpoint AS endpoint,
    nodes.allowed_ips AS allowed_ips,
    nodes.available_zones AS available_zones,
    nodes.grpc_port AS grpc_port,
    nodes.raft_port AS raft_port,
    nodes.network_ipv6 AS network_ipv6,
    nodes.updated_at AS updated_at,
    nodes.created_at AS created_at,
    COALESCE(leases.ipv4, '') AS private_address_v4
FROM nodes
LEFT OUTER JOIN leases ON nodes.id = leases.node_id
LEFT OUTER JOIN asns ON nodes.id = asns.node_id
WHERE nodes.id <> ?;

-- name: GetNodePeer :one
SELECT
    nodes.id AS id,
    nodes.public_key AS public_key,
    COALESCE(asns.asn, 0) AS asn,
    nodes.endpoint AS endpoint,
    nodes.allowed_ips AS allowed_ips,
    nodes.grpc_port AS grpc_port,
    nodes.raft_port AS raft_port,
    nodes.network_ipv6 AS network_ipv6,
    COALESCE(leases.ipv4, '') AS private_address_v4
FROM nodes
LEFT OUTER JOIN leases ON nodes.id = leases.node_id
LEFT OUTER JOIN asns ON nodes.id = asns.node_id
WHERE nodes.id = ?;
