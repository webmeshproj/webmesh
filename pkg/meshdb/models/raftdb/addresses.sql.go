// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.18.0
// source: addresses.sql

package raftdb

import (
	"context"
)

const GetNodePrivateRPCAddress = `-- name: GetNodePrivateRPCAddress :one
SELECT
    CAST(address AS TEXT) AS address
FROM node_private_rpc_addresses
WHERE node_id = ?
`

func (q *Queries) GetNodePrivateRPCAddress(ctx context.Context, nodeID string) (interface{}, error) {
	row := q.db.QueryRowContext(ctx, GetNodePrivateRPCAddress, nodeID)
	var address interface{}
	err := row.Scan(&address)
	return address, err
}

const GetNodePublicRPCAddress = `-- name: GetNodePublicRPCAddress :one
SELECT
    CAST(address AS TEXT) AS address
FROM node_public_rpc_addresses
WHERE node_id = ?
`

func (q *Queries) GetNodePublicRPCAddress(ctx context.Context, nodeID string) (interface{}, error) {
	row := q.db.QueryRowContext(ctx, GetNodePublicRPCAddress, nodeID)
	var address interface{}
	err := row.Scan(&address)
	return address, err
}

const GetPeerPrivateRPCAddresses = `-- name: GetPeerPrivateRPCAddresses :many
SELECT
    CAST(address AS TEXT) AS address
FROM node_private_rpc_addresses
WHERE node_id <> ?
`

func (q *Queries) GetPeerPrivateRPCAddresses(ctx context.Context, nodeID string) ([]interface{}, error) {
	rows, err := q.db.QueryContext(ctx, GetPeerPrivateRPCAddresses, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []interface{}
	for rows.Next() {
		var address interface{}
		if err := rows.Scan(&address); err != nil {
			return nil, err
		}
		items = append(items, address)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const ListPublicRPCAddresses = `-- name: ListPublicRPCAddresses :many
SELECT
    node_id AS node_id,
    CAST(address AS TEXT) AS address
FROM node_public_rpc_addresses
`

type ListPublicRPCAddressesRow struct {
	NodeID  string      `json:"node_id"`
	Address interface{} `json:"address"`
}

func (q *Queries) ListPublicRPCAddresses(ctx context.Context) ([]ListPublicRPCAddressesRow, error) {
	rows, err := q.db.QueryContext(ctx, ListPublicRPCAddresses)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []ListPublicRPCAddressesRow
	for rows.Next() {
		var i ListPublicRPCAddressesRow
		if err := rows.Scan(&i.NodeID, &i.Address); err != nil {
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