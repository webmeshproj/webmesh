-- name: DumpMeshState :many
SELECT * FROM mesh_state;

-- name: DropMeshState :exec
DELETE FROM mesh_state;

-- name: RestoreMeshState :exec
INSERT INTO mesh_state (key, value) VALUES (:key, :value);

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
    primary_endpoint,
    endpoints,
    network_ipv6,
    created_at,
    updated_at
) VALUES (
    :id,
    :public_key,
    :raft_port,
    :grpc_port,
    :wireguard_port,
    :primary_endpoint,
    :endpoints,
    :network_ipv6,
    :created_at,
    :updated_at
);

-- name: DumpLeases :many
SELECT * FROM leases;

-- name: DropLeases :exec
DELETE FROM leases;

-- name: RestoreLease :exec
INSERT INTO leases (
    node_id,
    ipv4,
    created_at
) VALUES (
    :node_id,
    :ipv4,
    :created_at
);
