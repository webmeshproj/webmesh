-- name: InsertNodeLease :one
INSERT OR REPLACE INTO leases (node_id, ipv4) VALUES (?, ?)
RETURNING *;

-- name: ReleaseNodeLease :exec
DELETE FROM leases WHERE node_id = ?;

-- name: ListAllocatedIPv4 :many
SELECT ipv4 FROM leases WHERE ipv4 IS NOT NULL;
