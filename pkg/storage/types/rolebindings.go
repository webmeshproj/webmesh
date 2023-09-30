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
func (rb RoleBinding) Proto() *v1.RoleBinding {
	return rb.RoleBinding
}

// DeepCopy returns a deep copy of the rolebinding.
func (rb RoleBinding) DeepCopy() RoleBinding {
	return RoleBinding{RoleBinding: rb.RoleBinding.DeepCopy()}
}

// DeepCopyInto copies the node into the given rolebinding.
func (rb RoleBinding) DeepCopyInto(role *RoleBinding) {
	*role = rb.DeepCopy()
}

// MarshalJSON marshals the rolebinding to JSON.
func (rb RoleBinding) MarshalJSON() ([]byte, error) {
	return protojson.Marshal(rb.RoleBinding)
}

// UnmarshalJSON unmarshals the rolebinding from JSON.
func (rb *RoleBinding) UnmarshalJSON(data []byte) error {
	var rolebinding v1.RoleBinding
	if err := protojson.Unmarshal(data, &rolebinding); err != nil {
		return err
	}
	rb.RoleBinding = &rolebinding
	return nil
}

// ContainsUserID returns true if the rolebinding contains the given user id.
func (rb RoleBinding) ContainsUserID(userID string) bool {
	for _, subject := range rb.GetSubjects() {
		if subject.GetType() == v1.SubjectType_SUBJECT_ALL || subject.GetType() == v1.SubjectType_SUBJECT_USER {
			if subject.GetName() == "*" || subject.GetName() == userID {
				return true
			}
		}
	}
	return false
}

// ContainsNodeID returns true if the rolebinding contains the given node id.
func (rb RoleBinding) ContainsNodeID(nodeID string) bool {
	for _, subject := range rb.GetSubjects() {
		if subject.GetType() == v1.SubjectType_SUBJECT_ALL || subject.GetType() == v1.SubjectType_SUBJECT_NODE {
			if subject.GetName() == "*" || subject.GetName() == nodeID {
				return true
			}
		}
	}
	return false
}
