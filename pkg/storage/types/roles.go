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

// RolesList is a list of roles. It contains methods for evaluating actions against
// contained permissions.
type RolesList []Role

// Role wraps a role.
type Role struct {
	*v1.Role `json:",inline"`
}

// Proto returns the underlying protobuf.
func (n Role) Proto() *v1.Role {
	return n.Role
}

// DeepCopy returns a deep copy of the role.
func (n Role) DeepCopy() Role {
	return Role{Role: n.Role.DeepCopy()}
}

// DeepCopyInto copies the node into the given role.
func (n Role) DeepCopyInto(role *Role) {
	*role = n.DeepCopy()
}

// MarshalProtoJSON marshals the role to JSON.
func (n Role) MarshalProtoJSON() ([]byte, error) {
	return protojson.Marshal(n.Role)
}

// UnmarshalProtoJSON unmarshals the role from JSON.
func (n *Role) UnmarshalProtoJSON(data []byte) error {
	var role v1.Role
	if err := protojson.Unmarshal(data, &role); err != nil {
		return err
	}
	n.Role = &role
	return nil
}

// Eval evaluates an action against the roles in the list.
func (l RolesList) Eval(action *v1.RBACAction) bool {
	if l == nil {
		return false
	}
	for _, role := range l {
		if EvalRole(role, action) {
			return true
		}
	}
	return false
}

// EvalRole evaluates an action against a single role.
func EvalRole(role Role, action *v1.RBACAction) bool {
	for _, p := range role.GetRules() {
		if EvalRule(p, action) {
			return true
		}
	}
	return false
}

// EvalRule evaluates an action against a single rule.
func EvalRule(rule *v1.Rule, action *v1.RBACAction) bool {
	var verbMatch bool
	for _, verb := range rule.GetVerbs() {
		if verb == action.GetVerb() || verb == v1.RuleVerb_VERB_ALL {
			verbMatch = true
			break
		}
	}
	if !verbMatch {
		return false
	}
	var resourceMatch bool
	var allResources bool
	for _, resource := range rule.GetResources() {
		if resource == action.GetResource() || resource == v1.RuleResource_RESOURCE_ALL {
			resourceMatch = true
			if resource == v1.RuleResource_RESOURCE_ALL {
				allResources = true
			}
			break
		}
	}
	if !resourceMatch {
		return false
	}
	if action.GetResourceName() == "" || allResources {
		return true
	}
	for _, resourceName := range rule.GetResourceNames() {
		if resourceName == action.GetResourceName() {
			return true
		}
	}
	return false
}
