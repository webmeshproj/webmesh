-- name: SetIPv6Prefix :exec
INSERT into mesh_state (key, value) VALUES ('IPv6Prefix', ?)
ON CONFLICT (key) DO UPDATE SET value = excluded.value;

-- name: GetIPv6Prefix :one
SELECT value FROM mesh_state WHERE key = 'IPv6Prefix';

-- name: SetIPv4Prefix :exec
INSERT into mesh_state (key, value) VALUES ('IPv4Prefix', ?)
ON CONFLICT (key) DO UPDATE SET value = excluded.value;

-- name: GetIPv4Prefix :one
SELECT value FROM mesh_state WHERE key = 'IPv4Prefix';

-- name: SetMeshDomain :exec
INSERT into mesh_state (key, value) VALUES ('MeshDomain', ?)
ON CONFLICT (key) DO UPDATE SET value = excluded.value;

-- name: GetMeshDomain :one
SELECT value FROM mesh_state WHERE key = 'MeshDomain';
