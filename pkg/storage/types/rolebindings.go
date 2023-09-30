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

// RoleBinding wraps a rolebinding.
type RoleBinding struct {
	*v1.RoleBinding `json:",inline"`
}

// Proto returns the underlying protobuf.
func (n RoleBinding) Proto() *v1.RoleBinding {
	return n.RoleBinding
}

// DeepCopy returns a deep copy of the rolebinding.
func (n RoleBinding) DeepCopy() RoleBinding {
	return RoleBinding{RoleBinding: n.RoleBinding.DeepCopy()}
}

// DeepCopyInto copies the node into the given rolebinding.
func (n RoleBinding) DeepCopyInto(role *RoleBinding) {
	*role = n.DeepCopy()
}

// MarshalJSON marshals the rolebinding to JSON.
func (n RoleBinding) MarshalJSON() ([]byte, error) {
	return protojson.Marshal(n.RoleBinding)
}

// UnmarshalJSON unmarshals the rolebinding from JSON.
func (n *RoleBinding) UnmarshalJSON(data []byte) error {
	var rb v1.RoleBinding
	if err := protojson.Unmarshal(data, &rb); err != nil {
		return err
	}
	n.RoleBinding = &rb
	return nil
}
