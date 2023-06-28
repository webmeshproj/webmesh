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
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/node/pkg/meshdb"
	"github.com/webmeshproj/node/pkg/meshdb/models"
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

// RBAC is the interface to the database models for RBAC.
type RBAC interface {
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
	PutGroup(ctx context.Context, role *v1.Group) error
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
func New(db meshdb.DB) RBAC {
	return &rbac{db}
}

type rbac struct {
	meshdb.DB
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
			return fmt.Errorf("cannot modify system role %q", role.GetName())
		}
	}
	q := models.New(r.Write())
	rules, err := json.Marshal(role.GetRules())
	if err != nil {
		return err
	}
	params := models.PutRoleParams{
		Name:      role.GetName(),
		RulesJson: string(rules),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	err = q.PutRole(ctx, params)
	if err != nil {
		return fmt.Errorf("put db role: %w", err)
	}
	return nil
}

// GetRole returns a role by name.
func (r *rbac) GetRole(ctx context.Context, name string) (*v1.Role, error) {
	role, err := models.New(r.Read()).GetRole(ctx, name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("get db role: %w", err)
	}
	return dbRoleToAPIRole(&role)
}

// DeleteRole deletes a role by name.
func (r *rbac) DeleteRole(ctx context.Context, name string) error {
	if IsSystemRole(name) {
		return fmt.Errorf("cannot delete system role %q", name)
	}
	q := models.New(r.Write())
	err := q.DeleteRole(ctx, name)
	if err != nil {
		return fmt.Errorf("delete db role: %w", err)
	}
	return nil
}

// ListRoles returns a list of all roles.
func (r *rbac) ListRoles(ctx context.Context) (RolesList, error) {
	roles, err := models.New(r.Read()).ListRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("list db roles: %w", err)
	}
	out := make(RolesList, len(roles))
	for i, role := range roles {
		out[i], err = dbRoleToAPIRole(&role)
		if err != nil {
			return nil, fmt.Errorf("convert db role: %w", err)
		}
	}
	return out, nil
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
			return fmt.Errorf("cannot modify system rolebinding %q", rolebinding.GetName())
		}
	}
	q := models.New(r.Write())
	params := models.PutRoleBindingParams{
		Name:      rolebinding.GetName(),
		RoleName:  rolebinding.GetRole(),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	var users, groups, nodes []string
	for _, subject := range rolebinding.GetSubjects() {
		switch subject.GetType() {
		case v1.SubjectType_SUBJECT_NODE:
			nodes = append(nodes, subject.GetName())
		case v1.SubjectType_SUBJECT_USER:
			users = append(users, subject.GetName())
		case v1.SubjectType_SUBJECT_GROUP:
			groups = append(groups, subject.GetName())
		case v1.SubjectType_SUBJECT_ALL:
			nodes = append(nodes, subject.GetName())
			users = append(users, subject.GetName())
			groups = append(groups, subject.GetName())
		}
	}
	if len(nodes) > 0 {
		params.NodeIds = sql.NullString{Valid: true, String: strings.Join(nodes, ",")}
	}
	if len(users) > 0 {
		params.UserNames = sql.NullString{Valid: true, String: strings.Join(users, ",")}
	}
	if len(groups) > 0 {
		params.GroupNames = sql.NullString{Valid: true, String: strings.Join(groups, ",")}
	}
	err := q.PutRoleBinding(ctx, params)
	if err != nil {
		return fmt.Errorf("put db rolebinding: %w", err)
	}
	return nil
}

// GetRoleBinding returns a rolebinding by name.
func (r *rbac) GetRoleBinding(ctx context.Context, name string) (*v1.RoleBinding, error) {
	q := models.New(r.Read())
	rb, err := q.GetRoleBinding(ctx, name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrRoleBindingNotFound
		}
		return nil, fmt.Errorf("get db rolebinding: %w", err)
	}
	return dbRoleBindingToAPIRoleBinding(&rb), nil
}

// DeleteRoleBinding deletes a rolebinding by name.
func (r *rbac) DeleteRoleBinding(ctx context.Context, name string) error {
	if IsSystemRoleBinding(name) {
		return fmt.Errorf("cannot delete system rolebinding %q", BootstrapVotersRoleBinding)
	}
	q := models.New(r.Write())
	err := q.DeleteRoleBinding(ctx, name)
	if err != nil {
		return fmt.Errorf("delete db rolebinding: %w", err)
	}
	return nil
}

// ListRoleBindings returns a list of all rolebindings.
func (r *rbac) ListRoleBindings(ctx context.Context) ([]*v1.RoleBinding, error) {
	q := models.New(r.Read())
	rbs, err := q.ListRoleBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("list db rolebindings: %w", err)
	}
	out := make([]*v1.RoleBinding, len(rbs))
	for i, rb := range rbs {
		out[i] = dbRoleBindingToAPIRoleBinding(&rb)
	}
	return out, nil
}

// PutGroup creates or updates a group.
func (r *rbac) PutGroup(ctx context.Context, role *v1.Group) error {
	q := models.New(r.Write())
	params := models.PutGroupParams{
		Name:      role.GetName(),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	var users, nodes []string
	for _, subject := range role.GetSubjects() {
		switch subject.GetType() {
		case v1.SubjectType_SUBJECT_NODE:
			nodes = append(nodes, subject.GetName())
		case v1.SubjectType_SUBJECT_USER:
			users = append(users, subject.GetName())
		case v1.SubjectType_SUBJECT_ALL:
			if subject.GetName() == "*" {
				nodes = append(nodes, subject.GetName())
				users = append(users, subject.GetName())
			}
		}
	}
	if len(nodes) > 0 {
		params.Nodes = sql.NullString{Valid: true, String: strings.Join(nodes, ",")}
	}
	if len(users) > 0 {
		params.Users = sql.NullString{Valid: true, String: strings.Join(users, ",")}
	}
	err := q.PutGroup(ctx, params)
	if err != nil {
		return fmt.Errorf("put db group: %w", err)
	}
	return nil
}

// GetGroup returns a group by name.
func (r *rbac) GetGroup(ctx context.Context, name string) (*v1.Group, error) {
	q := models.New(r.Read())
	group, err := q.GetGroup(ctx, name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrGroupNotFound
		}
		return nil, fmt.Errorf("get db group: %w", err)
	}
	return dbGroupToAPIGroup(&group), nil
}

// DeleteGroup deletes a group by name.
func (r *rbac) DeleteGroup(ctx context.Context, name string) error {
	q := models.New(r.Write())
	err := q.DeleteGroup(ctx, name)
	if err != nil {
		return fmt.Errorf("delete db group: %w", err)
	}
	return nil
}

// ListGroups returns a list of all groups.
func (r *rbac) ListGroups(ctx context.Context) ([]*v1.Group, error) {
	q := models.New(r.Read())
	groups, err := q.ListGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("list db groups: %w", err)
	}
	out := make([]*v1.Group, len(groups))
	for i, group := range groups {
		out[i] = dbGroupToAPIGroup(&group)
	}
	return out, nil
}

// ListNodeRoles returns a list of all roles for a node.
func (r *rbac) ListNodeRoles(ctx context.Context, nodeID string) (RolesList, error) {
	roles, err := models.New(r.Read()).ListBoundRolesForNode(ctx, models.ListBoundRolesForNodeParams{
		NodeIds: sql.NullString{
			String: nodeID,
			Valid:  true,
		},
		Nodes: sql.NullString{
			String: nodeID,
			Valid:  true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("list db roles: %w", err)
	}
	out := make(RolesList, len(roles))
	for i, role := range roles {
		out[i], err = dbRoleToAPIRole(&role)
		if err != nil {
			return nil, fmt.Errorf("convert db role: %w", err)
		}
	}
	return out, nil
}

// ListUserRoles returns a list of all roles for a user.
func (r *rbac) ListUserRoles(ctx context.Context, user string) (RolesList, error) {
	roles, err := models.New(r.Read()).ListBoundRolesForUser(ctx, models.ListBoundRolesForUserParams{
		UserNames: sql.NullString{
			String: user,
			Valid:  true,
		},
		Users: sql.NullString{
			String: user,
			Valid:  true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("list db roles: %w", err)
	}
	out := make(RolesList, len(roles))
	for i, role := range roles {
		out[i], err = dbRoleToAPIRole(&role)
		if err != nil {
			return nil, fmt.Errorf("convert db role: %w", err)
		}
	}
	return out, nil
}

func dbRoleToAPIRole(dbRole *models.Role) (*v1.Role, error) {
	out := &v1.Role{
		Name:  dbRole.Name,
		Rules: []*v1.Rule{},
	}
	err := json.Unmarshal([]byte(dbRole.RulesJson), &out.Rules)
	if err != nil {
		return nil, fmt.Errorf("unmarshal rules: %w", err)
	}
	return out, nil
}

func dbRoleBindingToAPIRoleBinding(dbRoleBinding *models.RoleBinding) *v1.RoleBinding {
	out := &v1.RoleBinding{
		Name:     dbRoleBinding.Name,
		Role:     dbRoleBinding.RoleName,
		Subjects: make([]*v1.Subject, 0),
	}
	if dbRoleBinding.UserNames.Valid {
		for _, user := range strings.Split(dbRoleBinding.UserNames.String, ",") {
			out.Subjects = append(out.Subjects, &v1.Subject{
				Type: v1.SubjectType_SUBJECT_USER,
				Name: user,
			})
		}
	}
	if dbRoleBinding.GroupNames.Valid {
		for _, group := range strings.Split(dbRoleBinding.GroupNames.String, ",") {
			out.Subjects = append(out.Subjects, &v1.Subject{
				Type: v1.SubjectType_SUBJECT_GROUP,
				Name: group,
			})
		}
	}
	if dbRoleBinding.NodeIds.Valid {
		for _, node := range strings.Split(dbRoleBinding.NodeIds.String, ",") {
			out.Subjects = append(out.Subjects, &v1.Subject{
				Type: v1.SubjectType_SUBJECT_NODE,
				Name: node,
			})
		}
	}
	// Check for the all case and squash down to a single subject.
	if len(out.Subjects) == 3 {
		alls := make([]bool, 3)
		for i, subject := range out.Subjects {
			if subject.Name == "*" {
				alls[i] = true
			} else {
				alls[i] = false
			}
		}
		if alls[0] && alls[1] && alls[2] {
			out.Subjects = []*v1.Subject{
				{
					Type: v1.SubjectType_SUBJECT_ALL,
					Name: "*",
				},
			}
		}
	}
	return out
}

func dbGroupToAPIGroup(dbGroup *models.Group) *v1.Group {
	out := &v1.Group{
		Name:     dbGroup.Name,
		Subjects: make([]*v1.Subject, 0),
	}
	if dbGroup.Users.Valid {
		for _, user := range strings.Split(dbGroup.Users.String, ",") {
			out.Subjects = append(out.Subjects, &v1.Subject{
				Type: v1.SubjectType_SUBJECT_USER,
				Name: user,
			})
		}
	}
	if dbGroup.Nodes.Valid {
		for _, node := range strings.Split(dbGroup.Nodes.String, ",") {
			out.Subjects = append(out.Subjects, &v1.Subject{
				Type: v1.SubjectType_SUBJECT_NODE,
				Name: node,
			})
		}
	}
	// Check for the all case and squash down to a single subject.
	if len(out.Subjects) == 2 {
		alls := make([]bool, 2)
		for i, subject := range out.Subjects {
			if subject.Name == "*" {
				alls[i] = true
			} else {
				alls[i] = false
			}
		}
		if alls[0] && alls[1] {
			out.Subjects = []*v1.Subject{
				{
					Type: v1.SubjectType_SUBJECT_ALL,
					Name: "*",
				},
			}
		}
	}
	return out
}
