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

package storage

import (
	"context"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

var (
	// MeshAdminRole is the name of the mesh admin role.
	MeshAdminRole = []byte("mesh-admin")
	// MeshAdminRoleBinding is the name of the mesh admin rolebinding.
	MeshAdminRoleBinding = []byte("mesh-admin")
	// VotersRole is the name of the voters role.
	VotersRole = []byte("voters")
	// VotersGroup is the name of the voters group.
	VotersGroup = []byte("voters")
	// BootstrapVotersRoleBinding is the name of the bootstrap voters rolebinding.
	BootstrapVotersRoleBinding = []byte("bootstrap-voters")
)

// RBAC is the interface to the database models for RBAC.
type RBAC interface {
	// Enable enables RBAC.
	Enable(ctx context.Context) error
	// Disable disables RBAC.
	Disable(ctx context.Context) error
	// IsDisabled returns true if RBAC is disabled.
	IsDisabled(ctx context.Context) (bool, error)

	// PutRole creates or updates a role.
	PutRole(ctx context.Context, role *v1.Role) error
	// GetRole returns a role by name.
	GetRole(ctx context.Context, name string) (*v1.Role, error)
	// DeleteRole deletes a role by name.
	DeleteRole(ctx context.Context, name string) error
	// ListRoles returns a list of all roles.
	ListRoles(ctx context.Context) (types.RolesList, error)

	// PutRoleBinding creates or updates a rolebinding.
	PutRoleBinding(ctx context.Context, rolebinding *v1.RoleBinding) error
	// GetRoleBinding returns a rolebinding by name.
	GetRoleBinding(ctx context.Context, name string) (*v1.RoleBinding, error)
	// DeleteRoleBinding deletes a rolebinding by name.
	DeleteRoleBinding(ctx context.Context, name string) error
	// ListRoleBindings returns a list of all rolebindings.
	ListRoleBindings(ctx context.Context) ([]*v1.RoleBinding, error)

	// PutGroup creates or updates a group.
	PutGroup(ctx context.Context, group *v1.Group) error
	// GetGroup returns a group by name.
	GetGroup(ctx context.Context, name string) (*v1.Group, error)
	// DeleteGroup deletes a group by name.
	DeleteGroup(ctx context.Context, name string) error
	// ListGroups returns a list of all groups.
	ListGroups(ctx context.Context) ([]*v1.Group, error)

	// ListNodeRoles returns a list of all roles for a node.
	ListNodeRoles(ctx context.Context, nodeID string) (types.RolesList, error)
	// ListUserRoles returns a list of all roles for a user.
	ListUserRoles(ctx context.Context, user string) (types.RolesList, error)
}

// IsSystemRole returns true if the role is a system role.
func IsSystemRole(name string) bool {
	return name == string(MeshAdminRole) || name == string(VotersRole)
}

// IsSystemRoleBinding returns true if the rolebinding is a system rolebinding.
func IsSystemRoleBinding(name string) bool {
	return name == string(MeshAdminRoleBinding) || name == string(BootstrapVotersRoleBinding)
}

// IsSystemGroup returns true if the group is a system group.
func IsSystemGroup(name string) bool {
	return name == string(VotersGroup)
}
