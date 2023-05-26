// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.18.0

package raftdb

import (
	"database/sql"
	"time"
)

type Lease struct {
	NodeID    string    `json:"node_id"`
	Ipv4      string    `json:"ipv4"`
	CreatedAt time.Time `json:"created_at"`
}

type MeshState struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type NetworkAcl struct {
	Name      string         `json:"name"`
	Proto     string         `json:"proto"`
	SrcCidrs  sql.NullString `json:"src_cidrs"`
	DstCidrs  sql.NullString `json:"dst_cidrs"`
	SrcNodes  sql.NullString `json:"src_nodes"`
	DstNodes  sql.NullString `json:"dst_nodes"`
	Action    string         `json:"action"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

type Node struct {
	ID              string         `json:"id"`
	PublicKey       sql.NullString `json:"public_key"`
	RaftPort        int64          `json:"raft_port"`
	GrpcPort        int64          `json:"grpc_port"`
	WireguardPort   int64          `json:"wireguard_port"`
	PrimaryEndpoint sql.NullString `json:"primary_endpoint"`
	Endpoints       sql.NullString `json:"endpoints"`
	NetworkIpv6     sql.NullString `json:"network_ipv6"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

type NodeAllWireguardEndpoint struct {
	NodeID    string       `json:"node_id"`
	Endpoints sql.NullBool `json:"endpoints"`
	Port      int64        `json:"port"`
}

type NodePrimaryWireguardEndpoint struct {
	NodeID  string       `json:"node_id"`
	Address sql.NullBool `json:"address"`
}

type NodePrivateRaftAddress struct {
	NodeID  string       `json:"node_id"`
	Address sql.NullBool `json:"address"`
}

type NodePrivateRpcAddress struct {
	NodeID  string       `json:"node_id"`
	Address sql.NullBool `json:"address"`
}

type NodePublicRaftAddress struct {
	NodeID  string       `json:"node_id"`
	Address sql.NullBool `json:"address"`
}

type NodePublicRpcAddress struct {
	NodeID  string       `json:"node_id"`
	Address sql.NullBool `json:"address"`
}