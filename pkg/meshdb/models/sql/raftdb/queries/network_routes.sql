-- name: PutNetworkRoute :exec
INSERT INTO network_routes (
    name,
    node,
    dst_cidrs,
    next_hop,
    created_at,
    updated_at
) VALUES (
    ?, ?, ?, ?, ?, ?
)
ON CONFLICT (name) DO UPDATE SET
    node = EXCLUDED.node,
    dst_cidrs = EXCLUDED.dst_cidrs,
    next_hop = EXCLUDED.next_hop,
    updated_at = EXCLUDED.updated_at;

-- name: GetNetworkRoute :one
SELECT * FROM network_routes WHERE name = ?;

-- name: ListNetworkRoutes :many
SELECT * FROM network_routes;

-- name: DeleteNetworkRoute :exec
DELETE FROM network_routes WHERE name = ?;

-- name: ListNetworkRoutesByNode :many
SELECT network_routes.* FROM network_routes
LEFT OUTER JOIN groups ON groups.nodes LIKE '%' || :node || '%'
WHERE network_routes.node = :node OR network_routes.node = 'group:' || groups.name;

-- name: ListNetworkRoutesByDstCidr :many
SELECT * FROM network_routes WHERE dst_cidrs LIKE '%' || ? || '%';
