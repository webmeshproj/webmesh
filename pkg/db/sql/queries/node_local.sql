-- name: SetCurrentWireguardKey :exec
INSERT into node_local (key, value) VALUES ('WireguardKey', ?)
ON CONFLICT (key) DO UPDATE SET value = excluded.value;

-- name: GetCurrentWireguardKey :one
SELECT value FROM node_local WHERE key = 'WireguardKey' LIMIT 1;