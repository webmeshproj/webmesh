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
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// StoragePeer wraps a storage peer.
type StoragePeer struct {
	*v1.StoragePeer `json:",inline"`
}

// Proto returns the underlying protobuf.
func (n StoragePeer) Proto() *v1.StoragePeer {
	return n.StoragePeer
}

// DeepCopy returns a deep copy of the peer.
func (n StoragePeer) DeepCopy() StoragePeer {
	return StoragePeer{StoragePeer: n.StoragePeer.DeepCopy()}
}

// DeepCopyInto copies the node into the given peer.
func (n StoragePeer) DeepCopyInto(group *StoragePeer) {
	*group = n.DeepCopy()
}

// MarshalProtoJSON marshals the peer to JSON.
func (n StoragePeer) MarshalProtoJSON() ([]byte, error) {
	return protojson.Marshal(n.StoragePeer)
}

// UnmarshalProtoJSON unmarshals the peer from JSON.
func (n *StoragePeer) UnmarshalProtoJSON(data []byte) error {
	var peer v1.StoragePeer
	if err := protojson.Unmarshal(data, &peer); err != nil {
		return err
	}
	n.StoragePeer = &peer
	return nil
}
