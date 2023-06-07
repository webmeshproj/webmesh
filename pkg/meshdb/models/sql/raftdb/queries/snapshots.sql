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
    primary_endpoint,
    wireguard_endpoints,
    zone_awareness_id,
    network_ipv6,
    created_at,
    updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

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

-- name: DumpRoles :many
SELECT * FROM roles;

-- name: DropRoles :exec
DELETE FROM roles;

-- name: RestoreRole :exec
INSERT INTO roles (
    name,
    rules_json,
    created_at,
    updated_at
) VALUES (?, ?, ?, ?);

-- name: DumpRoleBindings :many
SELECT * FROM role_bindings;

-- name: DropRoleBindings :exec
DELETE FROM role_bindings;

-- name: RestoreRoleBinding :exec
INSERT INTO role_bindings (
    name,
    role_name,
    node_ids,
    user_names,
    group_names,
    created_at,
    updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: DumpUsers :many
SELECT * FROM users;

-- name: DropUsers :exec
DELETE FROM users;

-- name: RestoreUser :exec
INSERT INTO users (
    name,
    created_at,
    updated_at
) VALUES (?, ?, ?);

-- name: DumpGroups :many
SELECT * FROM groups;

-- name: DropGroups :exec
DELETE FROM groups;

-- name: RestoreGroup :exec
INSERT INTO groups (
    name,
    users,
    nodes,
    created_at,
    updated_at
) VALUES (?, ?, ?, ?, ?);

-- name: DumpNetworkACLs :many
SELECT * FROM network_acls;

-- name: DropNetworkACLs :exec
DELETE FROM network_acls;

-- name: RestoreNetworkACL :exec
INSERT INTO network_acls (
    name,
    src_node_ids,
    dst_node_ids,
    src_cidrs,
    dst_cidrs,
    action,
    created_at,
    updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: DumpNodeEdges :many
SELECT * FROM node_edges;

-- name: DropNodeEdges :exec
DELETE FROM node_edges;

-- name: RestoreNodeEdge :exec
INSERT INTO node_edges (src_node_id, dst_node_id, weight, attrs) VALUES (?, ?, ?, ?);
