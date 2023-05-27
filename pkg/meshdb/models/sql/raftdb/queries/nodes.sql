-- name: GetNodeCount :one
SELECT COUNT(*) AS count FROM nodes;

-- name: InsertNode :one
INSERT INTO nodes (
    id,
    public_key,
    public_endpoint,
    network_ipv6,
    grpc_port,
    raft_port,
    wireguard_port,
    created_at,
    updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET
    public_key = EXCLUDED.public_key,
    public_endpoint = EXCLUDED.public_endpoint,
    network_ipv6 = EXCLUDED.network_ipv6,
    grpc_port = EXCLUDED.grpc_port,
    raft_port = EXCLUDED.raft_port,
    wireguard_port = EXCLUDED.wireguard_port,
    updated_at = EXCLUDED.updated_at
RETURNING *;

-- name: UpdateNode :one
UPDATE nodes SET
    public_key = ?,
    public_endpoint = ?,
    network_ipv6 = ?,
    grpc_port = ?,
    raft_port = ?,
    wireguard_port = ?,
    updated_at = ?
WHERE id = ?
RETURNING *;

-- name: DeleteNode :exec
DELETE FROM nodes WHERE id = ?;

-- name: GetNode :one
SELECT
    nodes.id AS id,
    nodes.public_key AS public_key,
    nodes.public_endpoint AS public_endpoint,
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

-- name: ListNodeIDs :many
SELECT nodes.id AS id FROM nodes;

-- name: ListNodes :many
SELECT
    nodes.id AS id,
    nodes.public_key AS public_key,
    nodes.public_endpoint AS public_endpoint,
    nodes.grpc_port AS grpc_port,
    nodes.raft_port AS raft_port,
    nodes.wireguard_port AS wireguard_port,
    nodes.network_ipv6 AS network_ipv6,
    COALESCE(leases.ipv4, '') AS private_address_v4,
    nodes.updated_at AS updated_at,
    nodes.created_at AS created_at
FROM nodes 
LEFT OUTER JOIN leases ON nodes.id = leases.node_id;
