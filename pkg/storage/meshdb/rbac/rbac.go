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
	"bytes"
	"context"
	"fmt"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

var (
	rolesPrefix        = storage.RegistryPrefix.ForString("roles")
	rolebindingsPrefix = storage.RegistryPrefix.ForString("rolebindings")
	groupsPrefix       = storage.RegistryPrefix.ForString("groups")
	rbacDisabledKey    = storage.RegistryPrefix.ForString("rbac-disabled")
)

type RBAC = storage.RBAC

// New returns a new RBAC.
func New(st storage.MeshStorage) RBAC {
	return &rbac{st}
}

type rbac struct {
	storage.MeshStorage
}

// Disable disables RBAC.
func (r *rbac) Disable(ctx context.Context) error {
	err := r.PutValue(ctx, rbacDisabledKey, []byte("true"), 0)
	if err != nil {
		return fmt.Errorf("put rbac disabled: %w", err)
	}
	return nil
}

// IsDisabled returns true if RBAC is disabled.
func (r *rbac) IsDisabled(ctx context.Context) (bool, error) {
	_, err := r.GetValue(ctx, rbacDisabledKey)
	if err != nil {
		if storage.IsKeyNotFoundError(err) {
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
	if storage.IsSystemRole(role.GetName()) {
		// Allow if the role doesn't exist yet.
		_, err := r.GetRole(ctx, role.GetName())
		if err != nil && err != storage.ErrRoleNotFound {
			return err
		}
		if err == nil {
			return fmt.Errorf("%w %q", storage.ErrIsSystemRole, role.GetName())
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
	key := rolesPrefix.ForString(role.GetName())
	err = r.PutValue(ctx, key, data, 0)
	if err != nil {
		return fmt.Errorf("put role: %w", err)
	}
	return nil
}

// GetRole returns a role by name.
func (r *rbac) GetRole(ctx context.Context, name string) (*v1.Role, error) {
	key := rolesPrefix.ForString(name)
	data, err := r.GetValue(ctx, key)
	if err != nil {
		if storage.IsKeyNotFoundError(err) {
			return nil, storage.ErrRoleNotFound
		}
		return nil, fmt.Errorf("get role: %w", err)
	}
	role := &v1.Role{}
	err = protojson.Unmarshal(data, role)
	if err != nil {
		return nil, fmt.Errorf("unmarshal role: %w", err)
	}
	return role, nil
}

// DeleteRole deletes a role by name.
func (r *rbac) DeleteRole(ctx context.Context, name string) error {
	if storage.IsSystemRole(name) {
		return fmt.Errorf("%w %q", storage.ErrIsSystemRole, name)
	}
	key := rolesPrefix.ForString(name)
	err := r.Delete(ctx, key)
	if err != nil {
		return fmt.Errorf("delete role: %w", err)
	}
	return nil
}

// ListRoles returns a list of all roles.
func (r *rbac) ListRoles(ctx context.Context) (types.RolesList, error) {
	out := make(types.RolesList, 0)
	err := r.IterPrefix(ctx, rolesPrefix, func(key, value []byte) error {
		if bytes.Equal(key, rolesPrefix) {
			return nil
		}
		role := &v1.Role{}
		err := protojson.Unmarshal(value, role)
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
	if storage.IsSystemRoleBinding(rolebinding.GetName()) {
		// Allow if the rolebinding doesn't exist yet.
		_, err := r.GetRoleBinding(ctx, rolebinding.GetName())
		if err != nil && err != storage.ErrRoleBindingNotFound {
			return err
		}
		if err == nil {
			return fmt.Errorf("%w %q", storage.ErrIsSystemRoleBinding, rolebinding.GetName())
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
	key := rolebindingsPrefix.ForString(rolebinding.GetName())
	data, err := protojson.Marshal(rolebinding)
	if err != nil {
		return fmt.Errorf("marshal rolebinding: %w", err)
	}
	err = r.PutValue(ctx, key, data, 0)
	if err != nil {
		return fmt.Errorf("put rolebinding: %w", err)
	}
	return nil
}

// GetRoleBinding returns a rolebinding by name.
func (r *rbac) GetRoleBinding(ctx context.Context, name string) (*v1.RoleBinding, error) {
	key := rolebindingsPrefix.ForString(name)
	data, err := r.GetValue(ctx, key)
	if err != nil {
		if storage.IsKeyNotFoundError(err) {
			return nil, storage.ErrRoleBindingNotFound
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
	if storage.IsSystemRoleBinding(name) {
		return fmt.Errorf("%w %q", storage.ErrIsSystemRoleBinding, name)
	}
	key := rolebindingsPrefix.ForString(name)
	err := r.Delete(ctx, key)
	if err != nil {
		return fmt.Errorf("delete rolebinding: %w", err)
	}
	return nil
}

// ListRoleBindings returns a list of all rolebindings.
func (r *rbac) ListRoleBindings(ctx context.Context) ([]*v1.RoleBinding, error) {
	out := make([]*v1.RoleBinding, 0)
	err := r.IterPrefix(ctx, rolebindingsPrefix, func(key, value []byte) error {
		if bytes.Equal(key, rolebindingsPrefix) {
			return nil
		}
		rolebinding := &v1.RoleBinding{}
		err := protojson.Unmarshal(value, rolebinding)
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
	key := groupsPrefix.ForString(group.GetName())
	data, err := protojson.Marshal(group)
	if err != nil {
		return fmt.Errorf("marshal group: %w", err)
	}
	err = r.PutValue(ctx, key, data, 0)
	if err != nil {
		return fmt.Errorf("put group: %w", err)
	}
	return nil
}

// GetGroup returns a group by name.
func (r *rbac) GetGroup(ctx context.Context, name string) (*v1.Group, error) {
	key := groupsPrefix.ForString(name)
	data, err := r.GetValue(ctx, key)
	if err != nil {
		if storage.IsKeyNotFoundError(err) {
			return nil, storage.ErrGroupNotFound
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
	if storage.IsSystemGroup(name) {
		return fmt.Errorf("%w %q", storage.ErrIsSystemGroup, name)
	}
	key := groupsPrefix.ForString(name)
	err := r.Delete(ctx, key)
	if err != nil {
		return fmt.Errorf("delete group: %w", err)
	}
	return nil
}

// ListGroups returns a list of all groups.
func (r *rbac) ListGroups(ctx context.Context) ([]*v1.Group, error) {
	out := make([]*v1.Group, 0)
	err := r.IterPrefix(ctx, groupsPrefix, func(key, value []byte) error {
		if bytes.Equal(key, groupsPrefix) {
			return nil
		}
		group := &v1.Group{}
		err := protojson.Unmarshal(value, group)
		if err != nil {
			return fmt.Errorf("unmarshal group: %w", err)
		}
		out = append(out, group)
		return nil
	})
	return out, err
}

// ListNodeRoles returns a list of all roles for a node.
func (r *rbac) ListNodeRoles(ctx context.Context, nodeID string) (types.RolesList, error) {
	rbs, err := r.ListRoleBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("list rolebindings: %w", err)
	}
	out := make(types.RolesList, 0)
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
func (r *rbac) ListUserRoles(ctx context.Context, user string) (types.RolesList, error) {
	rbs, err := r.ListRoleBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("list rolebindings: %w", err)
	}
	out := make(types.RolesList, 0)
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
