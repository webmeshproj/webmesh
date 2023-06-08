-- name: PutNetworkRoute :exec
INSERT INTO network_routes (
    name,
    nodes,
    dst_cidrs,
    next_hops,
    created_at,
    updated_at
) VALUES (
    ?, ?, ?, ?, ?, ?
)
ON CONFLICT (name) DO UPDATE SET
    nodes = EXCLUDED.nodes,
    dst_cidrs = EXCLUDED.dst_cidrs,
    next_hops = EXCLUDED.next_hops,
    updated_at = EXCLUDED.updated_at;

-- name: GetNetworkRoute :one
SELECT * FROM network_routes WHERE name = ?;

-- name: ListNetworkRoutes :many
SELECT * FROM network_routes;

-- name: DeleteNetworkRoute :exec
DELETE FROM network_routes WHERE name = ?;

-- name: ListNetworkRoutesByNode :many
SELECT * FROM network_routes WHERE nodes LIKE '%' || ? || '%';

-- name: ListNetworkRoutesByDstCidr :many
SELECT * FROM network_routes WHERE dst_cidrs LIKE '%' || ? || '%';
