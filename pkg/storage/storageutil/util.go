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

// Package storageutil contains utility functions for mesh database interactions.
package storageutil

import (
	"strings"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slices"
)

// InvalidIDChars are the characters that are not allowed in node IDs.
var InvalidIDChars = []rune{'/', '\\', ':', '*', '?', '"', '\'', '<', '>', '|', ','}

// ReservedNodeIDs are reserved node IDs.
var ReservedNodeIDs = []string{"self", "local", "localhost", "leader", "voters", "observers"}

// IsValidID returns true if the given identifier is valid and safe to be saved to storage.
func IsValidID(id string) bool {
	// Make sure non-empty and all characters are valid UTF-8.
	if !IsValidKey(id) {
		return false
	}
	for _, c := range InvalidIDChars {
		if strings.ContainsRune(id, c) {
			return false
		}
	}
	return true
}

// IsValidNodeID returns true if the given node ID is valid and safe to be saved to storage.
func IsValidNodeID(id string) bool {
	if !IsValidID(id) {
		return false
	}
	return !slices.Contains(ReservedNodeIDs, id)
}

// IsValidKey reports that a key is valid. All keys must be non-empty and valid UTF-8.
func IsValidKey(key string) bool {
	if len(key) == 0 {
		return false
	}
	// Make sure all characters are valid UTF-8.
	if validated := strings.ToValidUTF8(key, "/"); validated != key {
		return false
	}
	return true
}

// EdgeAttrsForConnectProto returns the edge attributes for the given protocol.
func EdgeAttrsForConnectProto(proto v1.ConnectProtocol) map[string]string {
	attrs := map[string]string{}
	switch proto {
	case v1.ConnectProtocol_CONNECT_ICE:
		attrs[v1.EdgeAttribute_EDGE_ATTRIBUTE_ICE.String()] = "true"
	case v1.ConnectProtocol_CONNECT_LIBP2P:
		attrs[v1.EdgeAttribute_EDGE_ATTRIBUTE_LIBP2P.String()] = "true"
	default:
		attrs[v1.EdgeAttribute_EDGE_ATTRIBUTE_NATIVE.String()] = "true"
	}
	return attrs
}

// ConnectProtoFromEdgeAttrs returns the protocol for the given edge attributes.
func ConnectProtoFromEdgeAttrs(attrs map[string]string) v1.ConnectProtocol {
	if attrs == nil {
		return v1.ConnectProtocol_CONNECT_NATIVE
	}
	if _, ok := attrs[v1.EdgeAttribute_EDGE_ATTRIBUTE_ICE.String()]; ok {
		return v1.ConnectProtocol_CONNECT_ICE
	}
	if _, ok := attrs[v1.EdgeAttribute_EDGE_ATTRIBUTE_LIBP2P.String()]; ok {
		return v1.ConnectProtocol_CONNECT_LIBP2P
	}
	return v1.ConnectProtocol_CONNECT_NATIVE
}
