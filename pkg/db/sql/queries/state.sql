-- name: SetULAPrefix :exec
INSERT into mesh_state (key, value) VALUES ('ULAPrefix', ?)
ON CONFLICT (key) DO UPDATE SET value = excluded.value;

-- name: GetULAPrefix :one
SELECT value FROM mesh_state WHERE key = 'ULAPrefix' LIMIT 1;

-- name: SetIPv4Prefix :exec
INSERT into mesh_state (key, value) VALUES ('IPv4Prefix', ?)
ON CONFLICT (key) DO UPDATE SET value = excluded.value;

-- name: GetIPv4Prefix :one
SELECT value FROM mesh_state WHERE key = 'IPv4Prefix' LIMIT 1;

-- name: SetLastAppliedRaftIndex :exec
INSERT into mesh_state (key, value) VALUES ('LastAppliedRaftIndex', ?)
ON CONFLICT (key) DO UPDATE SET value = excluded.value;

-- name: SetCurrentRaftTerm :exec
INSERT into mesh_state (key, value) VALUES ('CurrentRaftTerm', ?)
ON CONFLICT (key) DO UPDATE SET value = excluded.value;

-- name: GetRaftState :one
SELECT 
    COALESCE((
        SELECT value FROM mesh_state WHERE key = 'CurrentRaftTerm'
    ), '') AS CurrentRaftTerm,
    COALESCE((
        SELECT value FROM mesh_state WHERE key = 'LastAppliedRaftIndex'
    ), '') AS LastAppliedRaftIndex;
