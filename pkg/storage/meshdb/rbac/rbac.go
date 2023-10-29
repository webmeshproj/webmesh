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
	"strconv"

	v1 "github.com/webmeshproj/api/go/v1"

	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

var (
	rolesPrefix        = types.RegistryPrefix.ForString("roles")
	rolebindingsPrefix = types.RegistryPrefix.ForString("rolebindings")
	groupsPrefix       = types.RegistryPrefix.ForString("groups")
	rbacDisabledKey    = types.RegistryPrefix.ForString("rbac-disabled")
)

type RBAC = storage.RBAC

// New returns a new RBAC.
func New(st storage.MeshStorage) RBAC {
	return &rbac{st}
}

type rbac struct {
	storage.MeshStorage
}

// GetEnabled returns the RBAC enabled state.
func (r *rbac) GetEnabled(ctx context.Context) (bool, error) {
	val, err := r.GetValue(ctx, rbacDisabledKey)
	if err != nil {
		// Not present we assume is true.
		if errors.IsKeyNotFound(err) {
			return true, nil
		}
		return false, fmt.Errorf("get rbac disabled: %w", err)
	}
	return strconv.ParseBool(string(val))
}

// SetEnabled sets the RBAC enabled state.
func (r *rbac) SetEnabled(ctx context.Context, enabled bool) error {
	err := r.PutValue(ctx, rbacDisabledKey, []byte(fmt.Sprintf("%v", enabled)), 0)
	if err != nil {
		return fmt.Errorf("put rbac disabled: %w", err)
	}
	return nil
}

// PutRole creates or updates a role.
func (r *rbac) PutRole(ctx context.Context, role types.Role) error {
	if storage.IsSystemRole(role.GetName()) {
		// Allow if the role doesn't exist yet.
		_, err := r.GetRole(ctx, role.GetName())
		if err != nil && !errors.IsRoleNotFound(err) {
			return err
		}
		if err == nil {
			return fmt.Errorf("%w %q", errors.ErrIsSystemRole, role.GetName())
		}
	}
	err := role.Validate()
	if err != nil {
		return fmt.Errorf("validate role: %w", err)
	}
	data, err := role.MarshalProtoJSON()
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
func (r *rbac) GetRole(ctx context.Context, name string) (out types.Role, err error) {
	key := rolesPrefix.ForString(name)
	data, err := r.GetValue(ctx, key)
	if err != nil {
		if errors.IsKeyNotFound(err) {
			return out, errors.ErrRoleNotFound
		}
		return out, fmt.Errorf("get role: %w", err)
	}
	err = out.UnmarshalProtoJSON(data)
	if err != nil {
		err = fmt.Errorf("unmarshal role: %w", err)
	}
	return
}

// DeleteRole deletes a role by name.
func (r *rbac) DeleteRole(ctx context.Context, name string) error {
	if storage.IsSystemRole(name) {
		return fmt.Errorf("%w %q", errors.ErrIsSystemRole, name)
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
		role := types.Role{Role: &v1.Role{}}
		err := role.UnmarshalProtoJSON(value)
		if err != nil {
			return fmt.Errorf("unmarshal role: %w", err)
		}
		out = append(out, role)
		return nil
	})
	return out, err
}

// PutRoleBinding creates or updates a rolebinding.
func (r *rbac) PutRoleBinding(ctx context.Context, rolebinding types.RoleBinding) error {
	if storage.IsSystemRoleBinding(rolebinding.GetName()) {
		// Allow if the rolebinding doesn't exist yet.
		_, err := r.GetRoleBinding(ctx, rolebinding.GetName())
		if err != nil && !errors.IsRoleBindingNotFound(err) {
			return err
		}
		if err == nil {
			return fmt.Errorf("%w %q", errors.ErrIsSystemRoleBinding, rolebinding.GetName())
		}
	}
	err := rolebinding.Validate()
	if err != nil {
		return fmt.Errorf("validate rolebinding: %w", err)
	}
	key := rolebindingsPrefix.ForString(rolebinding.GetName())
	data, err := rolebinding.MarshalProtoJSON()
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
func (r *rbac) GetRoleBinding(ctx context.Context, name string) (out types.RoleBinding, err error) {
	key := rolebindingsPrefix.ForString(name)
	data, err := r.GetValue(ctx, key)
	if err != nil {
		if errors.IsKeyNotFound(err) {
			err = errors.ErrRoleBindingNotFound
			return
		}
		err = fmt.Errorf("get rolebinding: %w", err)
		return
	}
	err = out.UnmarshalProtoJSON(data)
	if err != nil {
		err = fmt.Errorf("unmarshal rolebinding: %w", err)
	}
	return
}

// DeleteRoleBinding deletes a rolebinding by name.
func (r *rbac) DeleteRoleBinding(ctx context.Context, name string) error {
	if storage.IsSystemRoleBinding(name) {
		return fmt.Errorf("%w %q", errors.ErrIsSystemRoleBinding, name)
	}
	key := rolebindingsPrefix.ForString(name)
	err := r.Delete(ctx, key)
	if err != nil {
		return fmt.Errorf("delete rolebinding: %w", err)
	}
	return nil
}

// ListRoleBindings returns a list of all rolebindings.
func (r *rbac) ListRoleBindings(ctx context.Context) ([]types.RoleBinding, error) {
	out := make([]types.RoleBinding, 0)
	err := r.IterPrefix(ctx, rolebindingsPrefix, func(key, value []byte) error {
		if bytes.Equal(key, rolebindingsPrefix) {
			return nil
		}
		rolebinding := types.RoleBinding{RoleBinding: &v1.RoleBinding{}}
		err := rolebinding.UnmarshalProtoJSON(value)
		if err != nil {
			return fmt.Errorf("unmarshal rolebinding: %w", err)
		}
		out = append(out, rolebinding)
		return nil
	})
	return out, err
}

// PutGroup creates or updates a group.
func (r *rbac) PutGroup(ctx context.Context, group types.Group) error {
	err := group.Validate()
	if err != nil {
		return fmt.Errorf("validate group: %w", err)
	}
	key := groupsPrefix.ForString(group.GetName())
	data, err := group.MarshalProtoJSON()
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
func (r *rbac) GetGroup(ctx context.Context, name string) (out types.Group, err error) {
	key := groupsPrefix.ForString(name)
	data, err := r.GetValue(ctx, key)
	if err != nil {
		if errors.IsKeyNotFound(err) {
			err = errors.ErrGroupNotFound
			return
		}
		err = fmt.Errorf("get group: %w", err)
		return
	}
	err = out.UnmarshalProtoJSON(data)
	if err != nil {
		err = fmt.Errorf("unmarshal group: %w", err)
	}
	return
}

// DeleteGroup deletes a group by name.
func (r *rbac) DeleteGroup(ctx context.Context, name string) error {
	if storage.IsSystemGroup(name) {
		return fmt.Errorf("%w %q", errors.ErrIsSystemGroup, name)
	}
	key := groupsPrefix.ForString(name)
	err := r.Delete(ctx, key)
	if err != nil {
		return fmt.Errorf("delete group: %w", err)
	}
	return nil
}

// ListGroups returns a list of all groups.
func (r *rbac) ListGroups(ctx context.Context) ([]types.Group, error) {
	out := make([]types.Group, 0)
	err := r.IterPrefix(ctx, groupsPrefix, func(key, value []byte) error {
		if bytes.Equal(key, groupsPrefix) {
			return nil
		}
		group := types.Group{Group: &v1.Group{}}
		err := group.UnmarshalProtoJSON(value)
		if err != nil {
			return fmt.Errorf("unmarshal group: %w", err)
		}
		out = append(out, group)
		return nil
	})
	return out, err
}

// ListNodeRoles returns a list of all roles for a node.
func (r *rbac) ListNodeRoles(ctx context.Context, nodeID types.NodeID) (types.RolesList, error) {
	rbs, err := r.ListRoleBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("list rolebindings: %w", err)
	}
	out := make(types.RolesList, 0)
	for _, rb := range rbs {
		if rb.ContainsNodeID(nodeID) {
			role, err := r.GetRole(ctx, rb.GetRole())
			if err != nil {
				return nil, fmt.Errorf("get role: %w", err)
			}
			out = append(out, role)
		}
	}
	return out, nil
}

// ListUserRoles returns a list of all roles for a user.
func (r *rbac) ListUserRoles(ctx context.Context, user types.NodeID) (types.RolesList, error) {
	rbs, err := r.ListRoleBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("list rolebindings: %w", err)
	}
	out := make(types.RolesList, 0)
	for _, rb := range rbs {
		if rb.ContainsUserID(user) {
			role, err := r.GetRole(ctx, rb.GetRole())
			if err != nil {
				return nil, fmt.Errorf("get role: %w", err)
			}
			out = append(out, role)
		}
	}
	return out, nil
}
