-- name: PutRole :exec
INSERT INTO roles (
    name, 
    rules_json, 
    created_at, 
    updated_at
) VALUES (
    ?, ?, ?, ?
)
ON CONFLICT (name) DO UPDATE SET 
    rules_json = excluded.rules_json, 
    updated_at = excluded.updated_at;

-- name: GetRole :one
SELECT * FROM roles WHERE name = ?;

-- name: DeleteRole :exec
DELETE FROM roles WHERE name = ?;

-- name: ListRoles :many
SELECT * FROM roles;

-- name: PutRoleBinding :exec
INSERT INTO role_bindings (
    name,
    role_name, 
    node_ids, 
    user_names,
    group_names,
    created_at, 
    updated_at
) VALUES (
    ?, ?, ?, ?, ?, ?, ?
)
ON CONFLICT (name) DO UPDATE SET 
    role_name = excluded.role_name, 
    node_ids = excluded.node_ids, 
    user_names = excluded.user_names, 
    group_names = excluded.group_names, 
    updated_at = excluded.updated_at;

-- name: GetRoleBinding :one
SELECT * FROM role_bindings WHERE name = ?;

-- name: DeleteRoleBinding :exec
DELETE FROM role_bindings WHERE name = ?;

-- name: ListRoleBindings :many
SELECT * FROM role_bindings;

-- name: ListBoundRolesForNode :many
SELECT DISTINCT roles.* FROM roles
JOIN role_bindings ON roles.name = role_bindings.role_name
LEFT OUTER JOIN groups ON role_bindings.group_names LIKE '%' || groups.name || '%'
WHERE 
    role_bindings.node_ids LIKE '%' || ? || '%' OR
    role_bindings.node_ids = '*' OR
    groups.nodes LIKE '%' || ? || '%';

-- name: ListBoundRolesForUser :many
SELECT DISTINCT roles.* FROM roles
JOIN role_bindings ON roles.name = role_bindings.role_name
LEFT OUTER JOIN groups ON role_bindings.group_names LIKE '%' || groups.name || '%'
WHERE 
    role_bindings.user_names LIKE '%' || ? || '%' OR
    role_bindings.user_names = '*' OR
    groups.users LIKE '%' || ? || '%';
