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
	"slices"
	"strings"
)

// InvalidIDChars are the characters that are not allowed in node IDs.
var InvalidIDChars = []rune{'/', '\\', ':', '*', '?', '"', '\'', '<', '>', '|', ',', ' '}

// ReservedNodeIDs are reserved node IDs.
var ReservedNodeIDs = []string{"self", "local", "localhost", "leader", "voters", "observers"}

// MaxIDLength is the maximum length of a key ID.
const MaxIDLength = 63

// IsValidID returns true if the given identifier is valid and safe to be saved to storage.
func IsValidID(id string) bool {
	// Make sure non-empty and all characters are valid UTF-8.
	if len(id) == 0 {
		return false
	}
	if len(id) > MaxIDLength {
		return false
	}
	// Make sure all characters are valid UTF-8.
	if validated := strings.ToValidUTF8(id, ""); validated != id {
		return false
	}
	for _, c := range InvalidIDChars {
		if strings.ContainsRune(id, c) {
			return false
		}
	}
	return true
}

// IsValidPathID returns true if the given identifier is valid and safe to be saved to storage.
func IsValidPathID(id string) bool {
	parts := strings.Split(strings.TrimPrefix(id, "/"), "/")
	for _, part := range parts {
		if !IsValidID(part) {
			return false
		}
	}
	return true
}

// IsValidIDOrWildcard returns true if the given identifier is valid and safe to be saved to storage.
// It also allows the wildcard character.
func IsValidIDOrWildcard(id string) bool {
	return id == "*" || IsValidID(id)
}

// TruncateID is a helper method to truncate IDs as needed when they are too long
// and can be safely truncated.
func TruncateID(id string) string {
	return TruncateIDTo(id, MaxIDLength)
}

// TruncateIDTo is a helper method to truncate IDs as needed when they are too long
// and can be safely truncated.
func TruncateIDTo(id string, length int) string {
	if len(id) > length {
		return id[:length]
	}
	return id
}

// IsValidNodeID returns true if the given node ID is valid and safe to be saved to storage.
func IsValidNodeID(id string) bool {
	if !IsValidID(id) {
		return false
	}
	return !slices.Contains(ReservedNodeIDs, id)
}

// NodeID is the type of a node ID.
type NodeID string

// String returns the string representation of the node ID.
func (id NodeID) String() string { return string(id) }

// Bytes returns the byte representation of the node ID.
func (id NodeID) Bytes() []byte { return []byte(id) }

// IsEmpty returns true if the node ID is empty.
func (id NodeID) IsEmpty() bool { return id == "" }

// IsValid returns true if the node ID is valid.
func (id NodeID) IsValid() bool {
	return !id.IsEmpty() && IsValidNodeID(id.String())
}
