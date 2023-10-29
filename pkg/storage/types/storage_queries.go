/*
Copyright 2023 Avi Zimmerman <avi.zimmerman@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package types

import (
	"net/netip"
	"strings"

	v1 "github.com/webmeshproj/api/go/v1"

	"github.com/webmeshproj/webmesh/pkg/storage/errors"
)

// StorageQuery represents a parsed storage query.
type StorageQuery struct {
	*v1.QueryRequest
	filters QueryFilters
}

// ParseStorageQuery parses a storage query.
func ParseStorageQuery(query *v1.QueryRequest) (StorageQuery, error) {
	filters := parseFilters(query)
	if query.GetCommand() == v1.QueryRequest_GET {
		// The filter should always contain an ID or pub key
		// unless its for raw network or rbac state.
		if query.GetType() == v1.QueryRequest_NETWORK_STATE || query.GetType() == v1.QueryRequest_RBAC_STATE {
			return StorageQuery{QueryRequest: query, filters: filters}, nil
		}
		if len(filters) == 0 {
			return StorageQuery{}, errors.ErrInvalidQuery
		}
		if query.GetType() == v1.QueryRequest_EDGES {
			// The query should have a source and target id
			if len(filters) != 2 {
				return StorageQuery{}, errors.ErrInvalidQuery
			}
			source, ok := filters.GetByType(FilterTypeSourceID)
			if !ok || source.Value == "" {
				return StorageQuery{}, errors.ErrInvalidQuery
			}
			if !IsValidID(source.Value) {
				return StorageQuery{}, errors.ErrInvalidQuery
			}
			target, ok := filters.GetByType(FilterTypeTargetID)
			if !ok || target.Value == "" {
				return StorageQuery{}, errors.ErrInvalidQuery
			}
			if !IsValidID(target.Value) {
				return StorageQuery{}, errors.ErrInvalidQuery
			}
			return StorageQuery{QueryRequest: query, filters: filters}, nil
		}
		if query.GetType() == v1.QueryRequest_PEERS {
			// We support either an ID or pubkey filter for peers.
			if len(filters) > 1 {
				return StorageQuery{}, errors.ErrInvalidQuery
			}
			id, ok := filters.GetByType(FilterTypeID)
			if !ok || id.Value == "" {
				pubkey, ok := filters.GetByType(FilterTypePubKey)
				if !ok || pubkey.Value == "" {
					return StorageQuery{}, errors.ErrInvalidQuery
				}
			} else if !IsValidID(id.Value) {
				return StorageQuery{}, errors.ErrInvalidQuery
			}
			return StorageQuery{QueryRequest: query, filters: filters}, nil
		}
		id, ok := filters.GetByType(FilterTypeID)
		if !ok || id.Value == "" {
			return StorageQuery{}, errors.ErrInvalidQuery
		}
		if !IsValidID(id.Value) {
			return StorageQuery{}, errors.ErrInvalidQuery
		}
		return StorageQuery{QueryRequest: query, filters: filters}, nil
	}
	// List queries don't require a filter.
	return StorageQuery{QueryRequest: query, filters: filters}, nil
}

// Filters returns the parsed filters for the query.
func (q StorageQuery) Filters() QueryFilters {
	return q.filters
}

// FilterType is the type of filter.
type FilterType string

const (
	FilterTypeID       = "id"       // Filter by the name or identifier.
	FilterTypeSourceID = "sourceid" // Filter an edge by source node ID.
	FilterTypeTargetID = "targetid" // Filter an edge by target node ID.
	FilterTypePubKey   = "pubkey"   // Filter a node by their public key.
	FilterTypeNodeID   = "nodeid"   // Filter an object by related node ID.
	FilterTypeCIDR     = "cidr"     // Filter a route by CIDR.
)

// IsValid returns true if the filter type is valid.
func (f FilterType) IsValid() bool {
	switch f {
	case FilterTypeID, FilterTypePubKey:
		return true
	default:
		return false
	}
}

// QueryFilters is a list of parsed filters for a storage query.
type QueryFilters []QueryFilter

// NewQueryFilters returns a new list of query filters.
func NewQueryFilters(filters ...QueryFilter) QueryFilters {
	return filters
}

// Encode encodes the query filters into a string.
func (q QueryFilters) Encode() string {
	var sb strings.Builder
	for i, filter := range q {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(string(filter.Type))
		sb.WriteString("=")
		sb.WriteString(filter.Value)
	}
	return sb.String()
}

func (q QueryFilters) WithID(id string) QueryFilters {
	return append(q, QueryFilter{
		Type:  FilterTypeID,
		Value: id,
	})
}

func (q QueryFilters) WithPubKey(pubkey string) QueryFilters {
	return append(q, QueryFilter{
		Type:  FilterTypePubKey,
		Value: pubkey,
	})
}

func (q QueryFilters) WithSourceNodeID(id NodeID) QueryFilters {
	return append(q, QueryFilter{
		Type:  FilterTypeSourceID,
		Value: string(id),
	})
}

func (q QueryFilters) WithTargetNodeID(id NodeID) QueryFilters {
	return append(q, QueryFilter{
		Type:  FilterTypeTargetID,
		Value: string(id),
	})
}

func (q QueryFilters) WithNodeID(id NodeID) QueryFilters {
	return append(q, QueryFilter{
		Type:  FilterTypeNodeID,
		Value: string(id),
	})
}

func (q QueryFilters) WithCIDR(cidr netip.Prefix) QueryFilters {
	return append(q, QueryFilter{
		Type:  FilterTypeCIDR,
		Value: cidr.String(),
	})
}

func (q QueryFilters) GetID() (string, bool) {
	for _, filter := range q {
		if filter.Type == FilterTypeID {
			return filter.Value, true
		}
	}
	return "", false
}

func (q QueryFilters) GetPubKey() (string, bool) {
	for _, filter := range q {
		if filter.Type == FilterTypePubKey {
			return filter.Value, true
		}
	}
	return "", false
}

func (q QueryFilters) GetSourceNodeID() (NodeID, bool) {
	for _, filter := range q {
		if filter.Type == FilterTypeSourceID {
			return NodeID(filter.Value), true
		}
	}
	return "", false
}

func (q QueryFilters) GetTargetNodeID() (NodeID, bool) {
	for _, filter := range q {
		if filter.Type == FilterTypeTargetID {
			return NodeID(filter.Value), true
		}
	}
	return "", false
}

func (q QueryFilters) GetNodeID() (NodeID, bool) {
	for _, filter := range q {
		if filter.Type == FilterTypeNodeID {
			return NodeID(filter.Value), true
		}
	}
	return "", false
}

func (q QueryFilters) GetCIDR() (netip.Prefix, bool) {
	for _, filter := range q {
		if filter.Type == FilterTypeCIDR {
			prefix, err := netip.ParsePrefix(filter.Value)
			if err != nil {
				return netip.Prefix{}, false
			}
			return prefix, true
		}
	}
	return netip.Prefix{}, false
}

func (q QueryFilters) GetByType(ftype FilterType) (QueryFilter, bool) {
	for _, filter := range q {
		if filter.Type == ftype {
			return filter, true
		}
	}
	return QueryFilter{}, false
}

// QueryFilter is a parsed filter for a storage query.
type QueryFilter struct {
	// The type of filter.
	Type FilterType
	// Value is the value of the filter.
	Value string
}

func parseFilters(req *v1.QueryRequest) QueryFilters {
	query := req.GetQuery()
	fields := strings.Split(query, ",")
	filters := make(QueryFilters, 0, len(fields))
	for _, field := range fields {
		parts := strings.Split(field, "=")
		if len(parts) != 2 {
			continue
		}
		ftype := FilterType(parts[0])
		if !ftype.IsValid() {
			continue
		}
		filters = append(filters, QueryFilter{
			Type:  ftype,
			Value: parts[1],
		})
	}
	return filters
}
