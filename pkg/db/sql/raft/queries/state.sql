-- name: SetULAPrefix :exec
INSERT into mesh_state (key, value) VALUES ('ULAPrefix', ?)
ON CONFLICT (key) DO UPDATE SET value = excluded.value;

-- name: GetULAPrefix :one
SELECT value FROM mesh_state WHERE key = 'ULAPrefix';

-- name: SetIPv4Prefix :exec
INSERT into mesh_state (key, value) VALUES ('IPv4Prefix', ?)
ON CONFLICT (key) DO UPDATE SET value = excluded.value;

-- name: GetIPv4Prefix :one
SELECT value FROM mesh_state WHERE key = 'IPv4Prefix';
