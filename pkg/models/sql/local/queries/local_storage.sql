-- name: SetCurrentWireguardKey :exec
INSERT OR REPLACE INTO wireguard_key (
    id, 
    private_key, 
    expires_at
) VALUES (1, ?, ?);

-- name: GetCurrentWireguardKey :one
SELECT * FROM wireguard_key LIMIT 1;

-- name: SetCurrentRaftIndex :exec
INSERT OR REPLACE INTO raft_index (
    id,
    term,
    log_index
) VALUES (1, ?, ?);

-- name: GetCurrentRaftIndex :one
SELECT * FROM raft_index LIMIT 1;
