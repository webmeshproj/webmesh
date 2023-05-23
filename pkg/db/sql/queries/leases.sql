-- name: InsertNodeLease :one
INSERT INTO leases (
    node_id, 
    ipv4,
    expires_at
) VALUES (
    ?, 
    ?, 
    ?
) 
ON CONFLICT(node_id) DO UPDATE SET
    expires_at = EXCLUDED.expires_at
RETURNING *;

-- name: ReleaseNodeLease :exec
DELETE FROM leases WHERE node_id = ?;

-- name: RenewNodeLease :exec
UPDATE leases SET expires_at = ? WHERE node_id = ?;

-- name: ListAllocatedIPv4 :many
SELECT ipv4 FROM leases WHERE ipv4 IS NOT NULL;
