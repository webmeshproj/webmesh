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

// Package rbac contains interfaces to the database models for RBAC.
package rbac

import (
	"context"
	"fmt"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/webmeshproj/webmesh/pkg/storage"
)

const (
	// MeshAdminRole is the name of the mesh admin role.
	MeshAdminRole = "mesh-admin"
	// MeshAdminRoleBinding is the name of the mesh admin rolebinding.
	MeshAdminRoleBinding = "mesh-admin"
	// VotersRole is the name of the voters role.
	VotersRole = "voters"
	// VotersGroup is the name of the voters group.
	VotersGroup = "voters"
	// BootstrapVotersRoleBinding is the name of the bootstrap voters rolebinding.
	BootstrapVotersRoleBinding = "bootstrap-voters"

	rolesPrefix        = "/registry/roles"
	rolebindingsPrefix = "/registry/rolebindings"
	groupsPrefix       = "/registry/groups"
	rbacDisabledKey    = "/registry/rbac-disabled"
)

// IsSystemRole returns true if the role is a system role.
func IsSystemRole(name string) bool {
	return name == MeshAdminRole || name == VotersRole
}

// IsSystemRoleBinding returns true if the rolebinding is a system rolebinding.
func IsSystemRoleBinding(name string) bool {
	return name == MeshAdminRoleBinding || name == BootstrapVotersRoleBinding
}

// IsSystemGroup returns true if the group is a system group.
func IsSystemGroup(name string) bool {
	return name == VotersGroup
}

// ErrRoleNotFound is returned when a role is not found.
var ErrRoleNotFound = fmt.Errorf("role not found")

// ErrRoleBindingNotFound is returned when a rolebinding is not found.
var ErrRoleBindingNotFound = fmt.Errorf("rolebinding not found")

// ErrGroupNotFound is returned when a group is not found.
var ErrGroupNotFound = fmt.Errorf("group not found")

// ErrIsSystemRole is returned when a system role is being modified.
var ErrIsSystemRole = fmt.Errorf("cannot modify system role")

// ErrIsSystemRoleBinding is returned when a system rolebinding is being modified.
var ErrIsSystemRoleBinding = fmt.Errorf("cannot modify system rolebinding")

// ErrIsSystemGroup is returned when a system group is being modified.
var ErrIsSystemGroup = fmt.Errorf("cannot modify system group")

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
	ListRoles(ctx context.Context) (RolesList, error)

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
	ListNodeRoles(ctx context.Context, nodeID string) (RolesList, error)
	// ListUserRoles returns a list of all roles for a user.
	ListUserRoles(ctx context.Context, user string) (RolesList, error)
}

// New returns a new RBAC.
func New(st storage.MeshStorage) RBAC {
	return &rbac{st}
}

type rbac struct {
	storage.MeshStorage
}

// Disable disables RBAC.
func (r *rbac) Disable(ctx context.Context) error {
	err := r.PutValue(ctx, rbacDisabledKey, "true", 0)
	if err != nil {
		return fmt.Errorf("put rbac disabled: %w", err)
	}
	return nil
}

// IsDisabled returns true if RBAC is disabled.
func (r *rbac) IsDisabled(ctx context.Context) (bool, error) {
	_, err := r.GetValue(ctx, rbacDisabledKey)
	if err != nil {
		if err == storage.ErrKeyNotFound {
			return false, nil
		}
		return false, fmt.Errorf("get rbac disabled: %w", err)
	}
	return true, nil
}

// Enable enables RBAC.
func (r *rbac) Enable(ctx context.Context) error {
	err := r.Delete(ctx, rbacDisabledKey)
	if err != nil {
		return fmt.Errorf("delete rbac disabled: %w", err)
	}
	return nil
}

// PutRole creates or updates a role.
func (r *rbac) PutRole(ctx context.Context, role *v1.Role) error {
	if IsSystemRole(role.GetName()) {
		// Allow if the role doesn't exist yet.
		_, err := r.GetRole(ctx, role.GetName())
		if err != nil && err != ErrRoleNotFound {
			return err
		}
		if err == nil {
			return fmt.Errorf("%w %q", ErrIsSystemRole, role.GetName())
		}
	}
	if role.GetName() == "" {
		return fmt.Errorf("role name cannot be empty")
	}
	if len(role.GetRules()) == 0 {
		return fmt.Errorf("role rules cannot be empty")
	}
	data, err := protojson.Marshal(role)
	if err != nil {
		return fmt.Errorf("marshal role: %w", err)
	}
	key := fmt.Sprintf("%s/%s", rolesPrefix, role.GetName())
	err = r.PutValue(ctx, key, string(data), 0)
	if err != nil {
		return fmt.Errorf("put role: %w", err)
	}
	return nil
}

// GetRole returns a role by name.
func (r *rbac) GetRole(ctx context.Context, name string) (*v1.Role, error) {
	key := fmt.Sprintf("%s/%s", rolesPrefix, name)
	data, err := r.GetValue(ctx, key)
	if err != nil {
		if err == storage.ErrKeyNotFound {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("get role: %w", err)
	}
	role := &v1.Role{}
	err = protojson.Unmarshal([]byte(data), role)
	if err != nil {
		return nil, fmt.Errorf("unmarshal role: %w", err)
	}
	return role, nil
}

// DeleteRole deletes a role by name.
func (r *rbac) DeleteRole(ctx context.Context, name string) error {
	if IsSystemRole(name) {
		return fmt.Errorf("%w %q", ErrIsSystemRole, name)
	}
	key := fmt.Sprintf("%s/%s", rolesPrefix, name)
	err := r.Delete(ctx, key)
	if err != nil {
		return fmt.Errorf("delete role: %w", err)
	}
	return nil
}

// ListRoles returns a list of all roles.
func (r *rbac) ListRoles(ctx context.Context) (RolesList, error) {
	out := make(RolesList, 0)
	err := r.IterPrefix(ctx, rolesPrefix, func(_, value string) error {
		role := &v1.Role{}
		err := protojson.Unmarshal([]byte(value), role)
		if err != nil {
			return fmt.Errorf("unmarshal role: %w", err)
		}
		out = append(out, role)
		return nil
	})
	return out, err
}

// PutRoleBinding creates or updates a rolebinding.
func (r *rbac) PutRoleBinding(ctx context.Context, rolebinding *v1.RoleBinding) error {
	if IsSystemRoleBinding(rolebinding.GetName()) {
		// Allow if the rolebinding doesn't exist yet.
		_, err := r.GetRoleBinding(ctx, rolebinding.GetName())
		if err != nil && err != ErrRoleBindingNotFound {
			return err
		}
		if err == nil {
			return fmt.Errorf("%w %q", ErrIsSystemRoleBinding, rolebinding.GetName())
		}
	}
	if rolebinding.GetName() == "" {
		return fmt.Errorf("rolebinding name cannot be empty")
	}
	if rolebinding.GetRole() == "" {
		return fmt.Errorf("rolebinding role cannot be empty")
	}
	if len(rolebinding.GetSubjects()) == 0 {
		return fmt.Errorf("rolebinding subjects cannot be empty")
	}
	key := fmt.Sprintf("%s/%s", rolebindingsPrefix, rolebinding.GetName())
	data, err := protojson.Marshal(rolebinding)
	if err != nil {
		return fmt.Errorf("marshal rolebinding: %w", err)
	}
	err = r.PutValue(ctx, key, string(data), 0)
	if err != nil {
		return fmt.Errorf("put rolebinding: %w", err)
	}
	return nil
}

// GetRoleBinding returns a rolebinding by name.
func (r *rbac) GetRoleBinding(ctx context.Context, name string) (*v1.RoleBinding, error) {
	key := fmt.Sprintf("%s/%s", rolebindingsPrefix, name)
	data, err := r.GetValue(ctx, key)
	if err != nil {
		if err == storage.ErrKeyNotFound {
			return nil, ErrRoleBindingNotFound
		}
		return nil, fmt.Errorf("get rolebinding: %w", err)
	}
	rolebinding := &v1.RoleBinding{}
	err = protojson.Unmarshal([]byte(data), rolebinding)
	if err != nil {
		return nil, fmt.Errorf("unmarshal rolebinding: %w", err)
	}
	return rolebinding, nil
}

// DeleteRoleBinding deletes a rolebinding by name.
func (r *rbac) DeleteRoleBinding(ctx context.Context, name string) error {
	if IsSystemRoleBinding(name) {
		return fmt.Errorf("%w %q", ErrIsSystemRoleBinding, name)
	}
	key := fmt.Sprintf("%s/%s", rolebindingsPrefix, name)
	err := r.Delete(ctx, key)
	if err != nil {
		return fmt.Errorf("delete rolebinding: %w", err)
	}
	return nil
}

// ListRoleBindings returns a list of all rolebindings.
func (r *rbac) ListRoleBindings(ctx context.Context) ([]*v1.RoleBinding, error) {
	out := make([]*v1.RoleBinding, 0)
	err := r.IterPrefix(ctx, rolebindingsPrefix, func(_, value string) error {
		rolebinding := &v1.RoleBinding{}
		err := protojson.Unmarshal([]byte(value), rolebinding)
		if err != nil {
			return fmt.Errorf("unmarshal rolebinding: %w", err)
		}
		out = append(out, rolebinding)
		return nil
	})
	return out, err
}

// PutGroup creates or updates a group.
func (r *rbac) PutGroup(ctx context.Context, group *v1.Group) error {
	if group.GetName() == "" {
		return fmt.Errorf("group name cannot be empty")
	}
	if len(group.GetSubjects()) == 0 {
		return fmt.Errorf("group subjects cannot be empty")
	}
	key := fmt.Sprintf("%s/%s", groupsPrefix, group.GetName())
	data, err := protojson.Marshal(group)
	if err != nil {
		return fmt.Errorf("marshal group: %w", err)
	}
	err = r.PutValue(ctx, key, string(data), 0)
	if err != nil {
		return fmt.Errorf("put group: %w", err)
	}
	return nil
}

// GetGroup returns a group by name.
func (r *rbac) GetGroup(ctx context.Context, name string) (*v1.Group, error) {
	key := fmt.Sprintf("%s/%s", groupsPrefix, name)
	data, err := r.GetValue(ctx, key)
	if err != nil {
		if err == storage.ErrKeyNotFound {
			return nil, ErrGroupNotFound
		}
		return nil, fmt.Errorf("get group: %w", err)
	}
	group := &v1.Group{}
	err = protojson.Unmarshal([]byte(data), group)
	if err != nil {
		return nil, fmt.Errorf("unmarshal group: %w", err)
	}
	return group, nil
}

// DeleteGroup deletes a group by name.
func (r *rbac) DeleteGroup(ctx context.Context, name string) error {
	if IsSystemGroup(name) {
		return fmt.Errorf("%w %q", ErrIsSystemGroup, name)
	}
	key := fmt.Sprintf("%s/%s", groupsPrefix, name)
	err := r.Delete(ctx, key)
	if err != nil {
		return fmt.Errorf("delete group: %w", err)
	}
	return nil
}

// ListGroups returns a list of all groups.
func (r *rbac) ListGroups(ctx context.Context) ([]*v1.Group, error) {
	out := make([]*v1.Group, 0)
	err := r.IterPrefix(ctx, groupsPrefix, func(_, value string) error {
		group := &v1.Group{}
		err := protojson.Unmarshal([]byte(value), group)
		if err != nil {
			return fmt.Errorf("unmarshal group: %w", err)
		}
		out = append(out, group)
		return nil
	})
	return out, err
}

// ListNodeRoles returns a list of all roles for a node.
func (r *rbac) ListNodeRoles(ctx context.Context, nodeID string) (RolesList, error) {
	rbs, err := r.ListRoleBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("list rolebindings: %w", err)
	}
	out := make(RolesList, 0)
RoleBindings:
	for _, rb := range rbs {
		for _, subject := range rb.GetSubjects() {
			if subject.GetType() == v1.SubjectType_SUBJECT_ALL || subject.GetType() == v1.SubjectType_SUBJECT_NODE {
				if subject.GetName() == "*" || subject.GetName() == nodeID {
					role, err := r.GetRole(ctx, rb.GetRole())
					if err != nil {
						return nil, fmt.Errorf("get role: %w", err)
					}
					out = append(out, role)
					continue RoleBindings
				}
			}
		}
	}
	return out, nil
}

// ListUserRoles returns a list of all roles for a user.
func (r *rbac) ListUserRoles(ctx context.Context, user string) (RolesList, error) {
	rbs, err := r.ListRoleBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("list rolebindings: %w", err)
	}
	out := make(RolesList, 0)
RoleBindings:
	for _, rb := range rbs {
		for _, subject := range rb.GetSubjects() {
			if subject.GetType() == v1.SubjectType_SUBJECT_ALL || subject.GetType() == v1.SubjectType_SUBJECT_USER {
				if subject.GetName() == "*" || subject.GetName() == user {
					role, err := r.GetRole(ctx, rb.GetRole())
					if err != nil {
						return nil, fmt.Errorf("get role: %w", err)
					}
					out = append(out, role)
					continue RoleBindings
				}
			}
		}
	}
	return out, nil
}
