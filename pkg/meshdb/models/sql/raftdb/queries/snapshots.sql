-- name: DumpMeshState :many
SELECT * FROM mesh_state;

-- name: DropMeshState :exec
DELETE FROM mesh_state;

-- name: RestoreMeshState :exec
INSERT INTO mesh_state (key, value) VALUES (?, ?);

-- name: DumpNodes :many
SELECT * FROM nodes;

-- name: DropNodes :exec
DELETE FROM nodes;

-- name: RestoreNode :exec
INSERT INTO nodes (
    id,
    public_key,
    raft_port,
    grpc_port,
    wireguard_port,
    public_endpoint,
    network_ipv6,
    created_at,
    updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DumpLeases :many
SELECT * FROM leases;

-- name: DropLeases :exec
DELETE FROM leases;

-- name: RestoreLease :exec
INSERT INTO leases (
    node_id,
    ipv4,
    created_at
) VALUES ( ?, ?, ? );
