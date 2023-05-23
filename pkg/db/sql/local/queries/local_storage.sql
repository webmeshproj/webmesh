-- name: SetCurrentWireguardKey :exec
INSERT into node_local (key, value) VALUES ('WireguardKey', ?)
ON CONFLICT (key) DO UPDATE SET value = excluded.value;

-- name: GetCurrentWireguardKey :one
SELECT value FROM node_local WHERE key = 'WireguardKey';

-- name: SetLastAppliedRaftIndex :exec
INSERT into node_local (key, value) VALUES ('LastAppliedRaftIndex', ?)
ON CONFLICT (key) DO UPDATE SET value = excluded.value;

-- name: SetCurrentRaftTerm :exec
INSERT into node_local (key, value) VALUES ('CurrentRaftTerm', ?)
ON CONFLICT (key) DO UPDATE SET value = excluded.value;

-- name: GetRaftState :one
SELECT 
    COALESCE((
        SELECT value FROM node_local WHERE key = 'CurrentRaftTerm'
    ), '') AS CurrentRaftTerm,
    COALESCE((
        SELECT value FROM node_local WHERE key = 'LastAppliedRaftIndex'
    ), '') AS LastAppliedRaftIndex;
