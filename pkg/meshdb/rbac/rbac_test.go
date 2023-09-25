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
	"errors"
	"testing"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/storage/backends/badgerdb"
)

const admin = "admin"

var roleSeeds = []*v1.Role{
	{
		Name: MeshAdminRole,
		Rules: []*v1.Rule{
			{
				Verbs:     []v1.RuleVerb{v1.RuleVerb_VERB_ALL},
				Resources: []v1.RuleResource{v1.RuleResource_RESOURCE_ALL},
			},
		},
	},
	{
		Name: VotersRole,
		Rules: []*v1.Rule{
			{
				Verbs:     []v1.RuleVerb{v1.RuleVerb_VERB_ALL},
				Resources: []v1.RuleResource{v1.RuleResource_RESOURCE_ALL},
			},
		},
	},
}

var roleBindingSeeds = []*v1.RoleBinding{
	{
		Name: MeshAdminRoleBinding,
		Role: MeshAdminRole,
		Subjects: []*v1.Subject{
			{
				Name: admin,
				Type: v1.SubjectType_SUBJECT_NODE,
			},
			{
				Name: admin,
				Type: v1.SubjectType_SUBJECT_USER,
			},
		},
	},
	{
		Name: BootstrapVotersRoleBinding,
		Role: VotersRole,
		Subjects: []*v1.Subject{
			{
				Name: VotersGroup,
				Type: v1.SubjectType_SUBJECT_GROUP,
			},
		},
	},
}

var groupSeeds = []*v1.Group{
	{
		Name: VotersGroup,
		Subjects: []*v1.Subject{
			{
				Name: admin,
				Type: v1.SubjectType_SUBJECT_NODE,
			},
		},
	},
}

func setupTest(t *testing.T) (*rbac, func()) {
	t.Helper()
	ctx := context.Background()
	st, err := badgerdb.New(badgerdb.Options{InMemory: true})
	if err != nil {
		t.Fatalf("create test db: %v", err)
	}
	close := func() {
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
	}
	r := New(st)
	for _, role := range roleSeeds {
		err = r.PutRole(ctx, role)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, roleBinding := range roleBindingSeeds {
		err = r.PutRoleBinding(ctx, roleBinding)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, group := range groupSeeds {
		err = r.PutGroup(ctx, group)
		if err != nil {
			t.Fatal(err)
		}
	}
	return r.(*rbac), close
}

func TestPutRole(t *testing.T) {
	t.Parallel()
	rbac, close := setupTest(t)
	defer close()

	tc := []struct {
		name    string
		role    *v1.Role
		ok      bool
		wantErr error
	}{
		{
			name:    "modify system role",
			role:    &v1.Role{Name: MeshAdminRole},
			ok:      false,
			wantErr: ErrIsSystemRole,
		},
		{
			name: "no role name",
			role: &v1.Role{
				Name: "",
				Rules: []*v1.Rule{
					{
						Verbs:     []v1.RuleVerb{v1.RuleVerb_VERB_ALL},
						Resources: []v1.RuleResource{v1.RuleResource_RESOURCE_ALL},
					},
				},
			},
			ok: false,
		},
		{
			name: "no role rules",
			role: &v1.Role{
				Name:  "foo",
				Rules: []*v1.Rule{},
			},
			ok: false,
		},
		{
			name: "valid role",
			role: &v1.Role{
				Name: "foo",
				Rules: []*v1.Rule{
					{
						Verbs:     []v1.RuleVerb{v1.RuleVerb_VERB_ALL},
						Resources: []v1.RuleResource{v1.RuleResource_RESOURCE_ALL},
					},
				},
			},
			ok: true,
		},
		{
			name: "update valid role",
			role: &v1.Role{
				Name: "foo",
				Rules: []*v1.Rule{
					{
						Verbs:     []v1.RuleVerb{v1.RuleVerb_VERB_PUT},
						Resources: []v1.RuleResource{v1.RuleResource_RESOURCE_ALL},
					},
				},
			},
			ok: true,
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			err := rbac.PutRole(context.Background(), tt.role)
			if tt.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatalf("expected error: %v", tt.wantErr)
			}
			if !tt.ok && tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error: %v, got: %v", tt.wantErr, err)
				}
			}
		})
	}
}

func TestGetRole(t *testing.T) {
	t.Parallel()
	rbac, close := setupTest(t)
	defer close()

	tc := []struct {
		name    string
		role    string
		ok      bool
		wantErr error
	}{
		{
			name: "get existing role",
			role: MeshAdminRole,
			ok:   true,
		},
		{
			name:    "non existing role",
			role:    "foo",
			ok:      false,
			wantErr: ErrRoleNotFound,
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			_, err := rbac.GetRole(context.Background(), tt.role)
			if tt.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatalf("expected error: %v", tt.wantErr)
			}
			if !tt.ok && tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error: %v, got: %v", tt.wantErr, err)
				}
			}
		})
	}
}

func TestDeleteRole(t *testing.T) {
	t.Parallel()
	rbac, close := setupTest(t)
	defer close()

	tc := []struct {
		name    string
		role    string
		ok      bool
		wantErr error
	}{
		{
			name:    "delete system role",
			role:    MeshAdminRole,
			ok:      false,
			wantErr: ErrIsSystemRole,
		},
		{
			name: "delete any other role",
			role: "foo",
			ok:   true,
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			err := rbac.DeleteRole(context.Background(), tt.role)
			if tt.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatalf("expected error: %v", tt.wantErr)
			}
			if !tt.ok && tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error: %v, got: %v", tt.wantErr, err)
				}
			}
		})
	}
}

func TestListRoles(t *testing.T) {
	t.Parallel()
	rbac, close := setupTest(t)
	defer close()

	roles, err := rbac.ListRoles(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != len(roleSeeds) {
		t.Fatalf("expected %d roles, got %d", len(roleSeeds), len(roles))
	}
}

func TestPutRoleBinding(t *testing.T) {
	t.Parallel()
	rbac, close := setupTest(t)
	defer close()

	tc := []struct {
		name    string
		rb      *v1.RoleBinding
		ok      bool
		wantErr error
	}{
		{
			name:    "modify system rolebinding",
			rb:      &v1.RoleBinding{Name: MeshAdminRoleBinding},
			ok:      false,
			wantErr: ErrIsSystemRoleBinding,
		},
		{
			name: "no rolebinding name",
			rb: &v1.RoleBinding{
				Name: "",
				Role: MeshAdminRole,
				Subjects: []*v1.Subject{
					{
						Type: v1.SubjectType_SUBJECT_ALL,
						Name: "*",
					},
				},
			},
			ok: false,
		},
		{
			name: "no role name",
			rb: &v1.RoleBinding{
				Name: "foo",
				Role: "",
				Subjects: []*v1.Subject{
					{
						Type: v1.SubjectType_SUBJECT_ALL,
						Name: "*",
					},
				},
			},
			ok: false,
		},
		{
			name: "no subjects",
			rb: &v1.RoleBinding{
				Name:     "foo",
				Role:     MeshAdminRole,
				Subjects: []*v1.Subject{},
			},
			ok: false,
		},
		{
			name: "valid rolebinding",
			rb: &v1.RoleBinding{
				Name: "foo",
				Role: MeshAdminRole,
				Subjects: []*v1.Subject{
					{
						Type: v1.SubjectType_SUBJECT_ALL,
						Name: "*",
					},
				},
			},
			ok: true,
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			err := rbac.PutRoleBinding(context.Background(), tt.rb)
			if tt.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatalf("expected error: %v", tt.wantErr)
			}
			if !tt.ok && tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error: %v, got: %v", tt.wantErr, err)
				}
			}
		})
	}

	// Check that foo got squashed on the roundtrip
	rb, err := rbac.GetRoleBinding(context.Background(), "foo")
	if err != nil {
		t.Fatal(err)
	}
	if rb.Name != "foo" {
		t.Fatalf("expected foo, got: %v", rb.Name)
	}
	if rb.Role != MeshAdminRole {
		t.Fatalf("expected %s, got: %s", MeshAdminRole, rb.Role)
	}
	if len(rb.Subjects) != 1 {
		t.Fatalf("expected 1 subject, got: %d", len(rb.Subjects))
	}
	if rb.Subjects[0].Name != "*" {
		t.Fatalf("expected *, got: %s", rb.Subjects[0].Name)
	}
	if rb.Subjects[0].Type != v1.SubjectType_SUBJECT_ALL {
		t.Fatalf("expected %s, got: %s", v1.SubjectType_SUBJECT_ALL, rb.Subjects[0].Type)
	}
}

func TestGetRoleBinding(t *testing.T) {
	t.Parallel()
	rbac, close := setupTest(t)
	defer close()

	tc := []struct {
		name    string
		rb      string
		ok      bool
		wantErr error
	}{
		{
			name: "get existing rolebinding",
			rb:   MeshAdminRole,
			ok:   true,
		},
		{
			name:    "non existing rolebinding",
			rb:      "foo",
			ok:      false,
			wantErr: ErrRoleBindingNotFound,
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			_, err := rbac.GetRoleBinding(context.Background(), tt.rb)
			if tt.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatalf("expected error: %v", tt.wantErr)
			}
			if !tt.ok && tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error: %v, got: %v", tt.wantErr, err)
				}
			}
		})
	}
}

func TestDeleteRoleBinding(t *testing.T) {
	t.Parallel()
	rbac, close := setupTest(t)
	defer close()

	tc := []struct {
		name    string
		rb      string
		ok      bool
		wantErr error
	}{
		{
			name:    "delete system rolebinding",
			rb:      MeshAdminRole,
			ok:      false,
			wantErr: ErrIsSystemRoleBinding,
		},
		{
			name: "delete any other rolebinding",
			rb:   "foo",
			ok:   true,
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			err := rbac.DeleteRoleBinding(context.Background(), tt.rb)
			if tt.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatalf("expected error: %v", tt.wantErr)
			}
			if !tt.ok && tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error: %v, got: %v", tt.wantErr, err)
				}
			}
		})
	}
}

func TestListRoleBindings(t *testing.T) {
	t.Parallel()
	rbac, close := setupTest(t)
	defer close()

	rbs, err := rbac.ListRoleBindings(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rbs) != len(roleBindingSeeds) {
		t.Fatalf("expected %d rolebindings, got %d", len(roleBindingSeeds), len(rbs))
	}
}

func TestPutGroup(t *testing.T) {
	t.Parallel()
	rbac, close := setupTest(t)
	defer close()

	tc := []struct {
		name    string
		group   *v1.Group
		ok      bool
		wantErr error
	}{
		{
			name: "no group name",
			group: &v1.Group{
				Name: "",
				Subjects: []*v1.Subject{
					{
						Type: v1.SubjectType_SUBJECT_ALL,
						Name: "*",
					},
				},
			},
			ok: false,
		},
		{
			name: "no subjects",
			group: &v1.Group{
				Name:     "foo",
				Subjects: []*v1.Subject{},
			},
			ok: false,
		},
		{
			name: "valid group",
			group: &v1.Group{
				Name: "foo",
				Subjects: []*v1.Subject{
					{
						Type: v1.SubjectType_SUBJECT_ALL,
						Name: "*",
					},
				},
			},
			ok: true,
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			err := rbac.PutGroup(context.Background(), tt.group)
			if tt.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatalf("expected error: %v", tt.wantErr)
			}
			if !tt.ok && tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error: %v, got: %v", tt.wantErr, err)
				}
			}
		})
	}

	// Check that foo got squashed on the roundtrip
	group, err := rbac.GetGroup(context.Background(), "foo")
	if err != nil {
		t.Fatal(err)
	}
	if group.Name != "foo" {
		t.Fatalf("expected foo, got: %v", group.Name)
	}
	if len(group.Subjects) != 1 {
		t.Fatalf("expected 1 subject, got: %d", len(group.Subjects))
	}
	if group.Subjects[0].Name != "*" {
		t.Fatalf("expected *, got: %s", group.Subjects[0].Name)
	}
	if group.Subjects[0].Type != v1.SubjectType_SUBJECT_ALL {
		t.Fatalf("expected %s, got: %s", v1.SubjectType_SUBJECT_ALL, group.Subjects[0].Type)
	}
}

func TestGetGroup(t *testing.T) {
	t.Parallel()
	rbac, close := setupTest(t)
	defer close()

	tc := []struct {
		name    string
		group   string
		ok      bool
		wantErr error
	}{
		{
			name:  "get existing group",
			group: VotersGroup,
			ok:    true,
		},
		{
			name:    "non existing rolebinding",
			group:   "foo",
			ok:      false,
			wantErr: ErrGroupNotFound,
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			_, err := rbac.GetGroup(context.Background(), tt.group)
			if tt.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatalf("expected error: %v", tt.wantErr)
			}
			if !tt.ok && tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error: %v, got: %v", tt.wantErr, err)
				}
			}
		})
	}
}

func TestDeleteGroup(t *testing.T) {
	t.Parallel()
	rbac, close := setupTest(t)
	defer close()

	tc := []struct {
		name    string
		group   string
		ok      bool
		wantErr error
	}{
		{
			name:    "delete system group",
			group:   VotersGroup,
			ok:      false,
			wantErr: ErrIsSystemGroup,
		},
		{
			name:  "delete any other group",
			group: "foo",
			ok:    true,
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			err := rbac.DeleteGroup(context.Background(), tt.group)
			if tt.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatalf("expected error: %v", tt.wantErr)
			}
			if !tt.ok && tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error: %v, got: %v", tt.wantErr, err)
				}
			}
		})
	}
}

func TestListGroups(t *testing.T) {
	t.Parallel()
	rbac, close := setupTest(t)
	defer close()

	groups, err := rbac.ListGroups(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(groups) != len(groupSeeds) {
		t.Fatalf("expected %d groups, got %d", len(groupSeeds), len(groups))
	}
}

func TestListNodeRoles(t *testing.T) {
	t.Parallel()
	rbac, close := setupTest(t)
	defer close()

	// Should only return the admin role for the admin user

	roles, err := rbac.ListUserRoles(context.Background(), admin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != 1 {
		t.Fatalf("expected 1 role, got %d", len(roles))
	}
	if roles[0].Name != MeshAdminRole {
		t.Fatalf("expected %s role, got %s", MeshAdminRole, roles[0].Name)
	}
}

func TestListUserRoles(t *testing.T) {
	t.Parallel()
	rbac, close := setupTest(t)
	defer close()

	// Should only return the admin role for the admin user

	roles, err := rbac.ListUserRoles(context.Background(), admin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != 1 {
		t.Fatalf("expected 1 role, got %d", len(roles))
	}
	if roles[0].Name != MeshAdminRole {
		t.Fatalf("expected %s role, got %s", MeshAdminRole, roles[0].Name)
	}
}
