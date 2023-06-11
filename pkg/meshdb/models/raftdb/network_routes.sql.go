// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.18.0
// source: network_routes.sql

package raftdb

import (
	"context"
	"database/sql"
	"time"
)

const DeleteNetworkRoute = `-- name: DeleteNetworkRoute :exec
DELETE FROM network_routes WHERE name = ?
`

func (q *Queries) DeleteNetworkRoute(ctx context.Context, name string) error {
	_, err := q.db.ExecContext(ctx, DeleteNetworkRoute, name)
	return err
}

const GetNetworkRoute = `-- name: GetNetworkRoute :one
SELECT name, node, dst_cidrs, next_hop, created_at, updated_at FROM network_routes WHERE name = ?
`

func (q *Queries) GetNetworkRoute(ctx context.Context, name string) (NetworkRoute, error) {
	row := q.db.QueryRowContext(ctx, GetNetworkRoute, name)
	var i NetworkRoute
	err := row.Scan(
		&i.Name,
		&i.Node,
		&i.DstCidrs,
		&i.NextHop,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const ListNetworkRoutes = `-- name: ListNetworkRoutes :many
SELECT name, node, dst_cidrs, next_hop, created_at, updated_at FROM network_routes
`

func (q *Queries) ListNetworkRoutes(ctx context.Context) ([]NetworkRoute, error) {
	rows, err := q.db.QueryContext(ctx, ListNetworkRoutes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []NetworkRoute
	for rows.Next() {
		var i NetworkRoute
		if err := rows.Scan(
			&i.Name,
			&i.Node,
			&i.DstCidrs,
			&i.NextHop,
			&i.CreatedAt,
			&i.UpdatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const ListNetworkRoutesByDstCidr = `-- name: ListNetworkRoutesByDstCidr :many
SELECT name, node, dst_cidrs, next_hop, created_at, updated_at FROM network_routes WHERE dst_cidrs LIKE '%' || ? || '%'
`

func (q *Queries) ListNetworkRoutesByDstCidr(ctx context.Context, dstCidrs string) ([]NetworkRoute, error) {
	rows, err := q.db.QueryContext(ctx, ListNetworkRoutesByDstCidr, dstCidrs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []NetworkRoute
	for rows.Next() {
		var i NetworkRoute
		if err := rows.Scan(
			&i.Name,
			&i.Node,
			&i.DstCidrs,
			&i.NextHop,
			&i.CreatedAt,
			&i.UpdatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const ListNetworkRoutesByNode = `-- name: ListNetworkRoutesByNode :many
SELECT network_routes.name, network_routes.node, network_routes.dst_cidrs, network_routes.next_hop, network_routes.created_at, network_routes.updated_at FROM network_routes
LEFT OUTER JOIN groups ON groups.nodes LIKE '%' || :node || '%'
WHERE network_routes.node = :node OR network_routes.node = 'group:' || groups.name
`

func (q *Queries) ListNetworkRoutesByNode(ctx context.Context, node string) ([]NetworkRoute, error) {
	rows, err := q.db.QueryContext(ctx, ListNetworkRoutesByNode, node)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []NetworkRoute
	for rows.Next() {
		var i NetworkRoute
		if err := rows.Scan(
			&i.Name,
			&i.Node,
			&i.DstCidrs,
			&i.NextHop,
			&i.CreatedAt,
			&i.UpdatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const PutNetworkRoute = `-- name: PutNetworkRoute :exec
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
    updated_at = EXCLUDED.updated_at
`

type PutNetworkRouteParams struct {
	Name      string         `json:"name"`
	Node      string         `json:"node"`
	DstCidrs  string         `json:"dst_cidrs"`
	NextHop   sql.NullString `json:"next_hop"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

func (q *Queries) PutNetworkRoute(ctx context.Context, arg PutNetworkRouteParams) error {
	_, err := q.db.ExecContext(ctx, PutNetworkRoute,
		arg.Name,
		arg.Node,
		arg.DstCidrs,
		arg.NextHop,
		arg.CreatedAt,
		arg.UpdatedAt,
	)
	return err
}