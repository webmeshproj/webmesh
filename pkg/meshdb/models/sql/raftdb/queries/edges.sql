-- name: InsertNodeEdge :exec
INSERT INTO node_edges (src_node_id, dst_node_id, weight, attrs) VALUES (?, ?, ?, ?);

-- name: UpdateNodeEdge :exec
UPDATE node_edges SET weight = ?, attrs = ? WHERE src_node_id = ? AND dst_node_id = ?;

-- name: NodeEdgeExists :one
SELECT 1 FROM node_edges WHERE src_node_id = ? AND dst_node_id = ?;

-- name: DeleteNodeEdge :exec
DELETE FROM node_edges WHERE src_node_id = ? AND dst_node_id = ?;

-- name: ListNodeEdges :many
SELECT * FROM node_edges;

-- name: GetNodeEdge :one
SELECT * FROM node_edges WHERE src_node_id = ? AND dst_node_id = ?;
