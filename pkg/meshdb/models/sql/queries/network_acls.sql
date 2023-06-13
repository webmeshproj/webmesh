-- name: PutNetworkACL :exec
INSERT INTO network_acls (
    name,
    priority,
    action,
    src_node_ids,
    dst_node_ids,
    src_cidrs,
    dst_cidrs,
    protocols,
    ports,
    created_at,
    updated_at
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
ON CONFLICT (name) DO UPDATE SET
    priority = EXCLUDED.priority,
    action = EXCLUDED.action,
    src_node_ids = EXCLUDED.src_node_ids,
    dst_node_ids = EXCLUDED.dst_node_ids,
    src_cidrs = EXCLUDED.src_cidrs,
    dst_cidrs = EXCLUDED.dst_cidrs,
    protocols = EXCLUDED.protocols,
    ports = EXCLUDED.ports,
    updated_at = EXCLUDED.updated_at;

-- name: GetNetworkACL :one
SELECT * FROM network_acls WHERE name = ?;

-- name: ListNetworkACLs :many
SELECT * FROM network_acls ORDER BY priority DESC;

-- name: DeleteNetworkACL :exec
DELETE FROM network_acls WHERE name = ?;
