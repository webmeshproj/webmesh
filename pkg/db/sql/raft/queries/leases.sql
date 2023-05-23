-- name: InsertNodeLease :one
INSERT INTO leases (node_id, ipv4) VALUES (?, ?) 
ON CONFLICT(node_id) DO UPDATE SET ipv4 = EXCLUDED.ipv4
RETURNING *;

-- name: ReleaseNodeLease :exec
DELETE FROM leases WHERE node_id = ?;

-- name: ListAllocatedIPv4 :many
SELECT ipv4 FROM leases WHERE ipv4 IS NOT NULL;
