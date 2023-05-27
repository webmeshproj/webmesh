-- name: PutRaftACL :exec
INSERT INTO raft_acls (
    name,
    nodes,
    action,
    created_at,
    updated_at
) VALUES (?, ?, ?, ?, ?) 
ON CONFLICT (name) DO UPDATE SET
    nodes = EXCLUDED.nodes,
    action = EXCLUDED.action,
    updated_at = EXCLUDED.updated_at;

-- name: DeleteRaftACL :exec
DELETE FROM raft_acls WHERE name = ?;

-- name: GetRaftACL :one
SELECT * FROM raft_acls WHERE name = ?;

-- name: ListRaftACLs :many
SELECT * FROM raft_acls;
