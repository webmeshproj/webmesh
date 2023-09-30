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

// Group wraps a group.
type Group struct {
	*v1.Group `json:",inline"`
}

// Proto returns the underlying protobuf.
func (n Group) Proto() *v1.Group {
	return n.Group
}

// DeepCopy returns a deep copy of the group.
func (n Group) DeepCopy() Group {
	return Group{Group: n.Group.DeepCopy()}
}

// DeepCopyInto copies the node into the given group.
func (n Group) DeepCopyInto(group *Group) {
	*group = n.DeepCopy()
}

// MarshalProtoJSON marshals the group to JSON.
func (n Group) MarshalProtoJSON() ([]byte, error) {
	return protojson.Marshal(n.Group)
}

// UnmarshalProtoJSON unmarshals the group from JSON.
func (n *Group) UnmarshalProtoJSON(data []byte) error {
	var grp v1.Group
	if err := protojson.Unmarshal(data, &grp); err != nil {
		return err
	}
	n.Group = &grp
	return nil
}
