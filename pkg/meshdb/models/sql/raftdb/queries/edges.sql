-- name: InsertNodeEdge :exec
INSERT OR REPLACE INTO node_edges (src_node_id, dst_node_id) VALUES (?, ?);

-- name: NodeEdgeExists :one
SELECT 1 FROM node_edges WHERE src_node_id = ? AND dst_node_id = ?;

-- name: DeleteNodeEdge :exec
DELETE FROM node_edges WHERE src_node_id = ? AND dst_node_id = ?;

-- name: ListNodeEdges :many
SELECT * FROM node_edges;

-- name: GetNodeEdges :many
SELECT dst_node_id FROM node_edges WHERE src_node_id = ?;
