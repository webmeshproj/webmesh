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
    primary_endpoint,
    additional_endpoints,
    zone_awareness_id,
    network_ipv6,
    created_at,
    updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

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

-- name: DumpRaftACLs :many
SELECT * FROM raft_acls;

-- name: DropRaftACLs :exec
DELETE FROM raft_acls;

-- name: RestoreRaftACL :exec
INSERT INTO raft_acls (
    name,
    nodes,
    action,
    created_at,
    updated_at
) VALUES (?, ?, ?, ?, ?);

-- name: DumpNodeEdges :many
SELECT * FROM node_edges;

-- name: DropNodeEdges :exec
DELETE FROM node_edges;

-- name: RestoreNodeEdge :exec
INSERT INTO node_edges (src_node_id, dst_node_id, weight, attrs) VALUES (?, ?, ?, ?);
