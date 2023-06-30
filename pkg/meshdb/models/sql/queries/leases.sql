-- name: InsertNodeLease :one
INSERT OR REPLACE INTO leases (node_id, ipv4, ipv6, created_at) VALUES (?, ?, ?, ?)
RETURNING *;

-- name: ReleaseNodeLease :exec
DELETE FROM leases WHERE node_id = ?;

-- name: ListAllocatedIPv4 :many
SELECT ipv4 FROM leases WHERE ipv4 IS NOT NULL;

-- name: ListAllocatedIPv6 :many
SELECT ipv6 FROM leases WHERE ipv6 IS NOT NULL;
