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

package testutil

import (
	"context"
	"testing"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// NewRBACFunc is a function that creates a new RBAC implementation.
type NewRBACFunc func() storage.RBAC

// TestRBACStorageConformance tests that an RBAC implementation conforms to the interface.
func TestRBACStorageConformance(t *testing.T, builder NewRBACFunc) {
	t.Run("PutRole", func(t *testing.T) {
		rbac := setupRBACTest(t, builder)
		tc := []struct {
			name    string
			role    *v1.Role
			ok      bool
			wantErr error
		}{
			{
				name:    "ModifySystemRole",
				role:    &v1.Role{Name: string(storage.MeshAdminRole)},
				ok:      false,
				wantErr: errors.ErrIsSystemRole,
			},
			{
				name: "NoName",
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
				name: "NoRules",
				role: &v1.Role{
					Name:  "foo",
					Rules: []*v1.Rule{},
				},
				ok: false,
			},
			{
				name: "PutValid",
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
				// TODO: Validity check
				name: "UpdateValid",
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
				err := rbac.PutRole(context.Background(), types.Role{Role: tt.role})
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
	})

	t.Run("GetRole", func(t *testing.T) {
		rbac := setupRBACTest(t, builder)
		tc := []struct {
			name    string
			role    string
			ok      bool
			wantErr error
		}{
			{
				name: "GetExistingRole",
				role: string(storage.MeshAdminRole),
				ok:   true,
			},
			{
				name:    "non existing role",
				role:    "foo",
				ok:      false,
				wantErr: errors.ErrRoleNotFound,
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
	})

	t.Run("DeleteRole", func(t *testing.T) {
		rbac := setupRBACTest(t, builder)
		tc := []struct {
			name    string
			role    string
			ok      bool
			wantErr error
		}{
			{
				name:    "DeleteSystemRole",
				role:    string(storage.MeshAdminRole),
				ok:      false,
				wantErr: errors.ErrIsSystemRole,
			},
			{
				name: "DeleteAnyRole",
				role: "foo",
				ok:   true,
			},
			// TODO: Existing role
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
	})

	t.Run("ListRoles", func(t *testing.T) {
		rbac := setupRBACTest(t, builder)
		roles, err := rbac.ListRoles(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(roles) != len(roleSeeds) {
			t.Fatalf("expected %d roles, got %d", len(roleSeeds), len(roles))
		}
		// TODO: Check that the roles are the same
	})

	t.Run("PutRoleBinding", func(t *testing.T) {
		rbac := setupRBACTest(t, builder)
		tc := []struct {
			name    string
			rb      *v1.RoleBinding
			ok      bool
			wantErr error
		}{
			{
				name:    "ModifySystemRoleBinding",
				rb:      &v1.RoleBinding{Name: string(storage.MeshAdminRoleBinding)},
				ok:      false,
				wantErr: errors.ErrIsSystemRoleBinding,
			},
			{
				name: "NoName",
				rb: &v1.RoleBinding{
					Name: "",
					Role: string(storage.MeshAdminRole),
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
				name: "NoRoleName",
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
				name: "NoSubjects",
				rb: &v1.RoleBinding{
					Name:     "foo",
					Role:     string(storage.MeshAdminRole),
					Subjects: []*v1.Subject{},
				},
				ok: false,
			},
			{
				name: "Valid",
				rb: &v1.RoleBinding{
					Name: "foo",
					Role: string(storage.MeshAdminRole),
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
				err := rbac.PutRoleBinding(context.Background(), types.RoleBinding{RoleBinding: tt.rb})
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
		t.Run("SquashSubjects", func(t *testing.T) {
			rb, err := rbac.GetRoleBinding(context.Background(), "foo")
			if err != nil {
				t.Fatal(err)
			}
			if rb.Name != "foo" {
				t.Fatalf("expected foo, got: %v", rb.Name)
			}
			if rb.Role != string(storage.MeshAdminRole) {
				t.Fatalf("expected %s, got: %s", storage.MeshAdminRole, rb.Role)
			}
			if len(rb.Subjects) != 1 {
				t.Fatalf("expected subjects to be squasheds, got: %d", len(rb.Subjects))
			}
			if rb.Subjects[0].Name != "*" {
				t.Fatalf("expected *, got: %s", rb.Subjects[0].Name)
			}
			if rb.Subjects[0].Type != v1.SubjectType_SUBJECT_ALL {
				t.Fatalf("expected %s, got: %s", v1.SubjectType_SUBJECT_ALL, rb.Subjects[0].Type)
			}
		})
	})

	t.Run("GetRoleBinding", func(t *testing.T) {
		rbac := setupRBACTest(t, builder)
		tc := []struct {
			name    string
			rb      string
			ok      bool
			wantErr error
		}{
			{
				name: "Existing",
				rb:   string(storage.MeshAdminRole),
				ok:   true,
			},
			{
				name:    "NonExisting",
				rb:      "foo",
				ok:      false,
				wantErr: errors.ErrRoleBindingNotFound,
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
	})

	t.Run("DeleteRoleBinding", func(t *testing.T) {
		rbac := setupRBACTest(t, builder)
		tc := []struct {
			name    string
			rb      string
			ok      bool
			wantErr error
		}{
			{
				name:    "SystemRoleBinding",
				rb:      string(storage.MeshAdminRole),
				ok:      false,
				wantErr: errors.ErrIsSystemRoleBinding,
			},
			{
				name: "AnyRoleBinding",
				rb:   "foo",
				ok:   true,
			},
			// TODO: Existing rolebinding
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
	})

	t.Run("ListRoleBindings", func(t *testing.T) {
		rbac := setupRBACTest(t, builder)
		rbs, err := rbac.ListRoleBindings(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rbs) != len(roleBindingSeeds) {
			t.Fatalf("expected %d rolebindings, got %d", len(roleBindingSeeds), len(rbs))
		}
		// TODO: Check that the rolebindings are the same
	})

	t.Run("PutGroup", func(t *testing.T) {
		rbac := setupRBACTest(t, builder)
		tc := []struct {
			name    string
			group   *v1.Group
			ok      bool
			wantErr error
		}{
			{
				name: "NoName",
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
				name: "NoSubjects",
				group: &v1.Group{
					Name:     "foo",
					Subjects: []*v1.Subject{},
				},
				ok: false,
			},
			{
				name: "Valid",
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
				err := rbac.PutGroup(context.Background(), types.Group{Group: tt.group})
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
		t.Run("SquashSubjects", func(t *testing.T) {
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
		})
	})

	t.Run("GetGroup", func(t *testing.T) {
		rbac := setupRBACTest(t, builder)
		tc := []struct {
			name    string
			group   string
			ok      bool
			wantErr error
		}{
			{
				name:  "Existing",
				group: string(storage.VotersGroup),
				ok:    true,
			},
			{
				name:    "NonExisting",
				group:   "foo",
				ok:      false,
				wantErr: errors.ErrGroupNotFound,
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
	})

	t.Run("DeleteGroup", func(t *testing.T) {
		rbac := setupRBACTest(t, builder)
		tc := []struct {
			name    string
			group   string
			ok      bool
			wantErr error
		}{
			{
				name:    "SystemGroup",
				group:   string(storage.VotersGroup),
				ok:      false,
				wantErr: errors.ErrIsSystemGroup,
			},
			{
				name:  "AnyGroup",
				group: "foo",
				ok:    true,
			},
			// TODO: Existing group
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
	})

	t.Run("ListGroups", func(t *testing.T) {
		rbac := setupRBACTest(t, builder)
		groups, err := rbac.ListGroups(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(groups) != len(groupSeeds) {
			t.Fatalf("expected %d groups, got %d", len(groupSeeds), len(groups))
		}
		// TODO: Check that the groups are the same
	})

	t.Run("ListNodeRoles", func(t *testing.T) {
		rbac := setupRBACTest(t, builder)
		roles, err := rbac.ListUserRoles(context.Background(), rbacTestAdmin)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(roles) != 1 {
			t.Fatalf("expected 1 role, got %d", len(roles))
		}
		if roles[0].Name != rbacTestAdmin {
			t.Fatalf("expected %s role, got %s", rbacTestAdmin, roles[0].Name)
		}
	})

	t.Run("ListUserRoles", func(t *testing.T) {
		rbac := setupRBACTest(t, builder)
		roles, err := rbac.ListUserRoles(context.Background(), rbacTestAdmin)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(roles) != 1 {
			t.Fatalf("expected 1 role, got %d", len(roles))
		}
		if roles[0].Name != rbacTestAdmin {
			t.Fatalf("expected %s role, got %s", rbacTestAdmin, roles[0].Name)
		}
	})
}

func setupRBACTest(t *testing.T, rbac NewRBACFunc) storage.RBAC {
	t.Helper()
	ctx := context.Background()
	st := rbac()
	for _, role := range roleSeeds {
		err := st.PutRole(ctx, types.Role{Role: role})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, roleBinding := range roleBindingSeeds {
		err := st.PutRoleBinding(ctx, types.RoleBinding{RoleBinding: roleBinding})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, group := range groupSeeds {
		err := st.PutGroup(ctx, types.Group{Group: group})
		if err != nil {
			t.Fatal(err)
		}
	}
	return st
}

var rbacTestAdmin = string(storage.MeshAdminRole)

var roleSeeds = []*v1.Role{
	{
		Name: string(storage.MeshAdminRole),
		Rules: []*v1.Rule{
			{
				Verbs:     []v1.RuleVerb{v1.RuleVerb_VERB_ALL},
				Resources: []v1.RuleResource{v1.RuleResource_RESOURCE_ALL},
			},
		},
	},
	{
		Name: string(storage.VotersRole),
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
		Name: string(storage.MeshAdminRoleBinding),
		Role: string(storage.MeshAdminRole),
		Subjects: []*v1.Subject{
			{
				Name: rbacTestAdmin,
				Type: v1.SubjectType_SUBJECT_NODE,
			},
			{
				Name: rbacTestAdmin,
				Type: v1.SubjectType_SUBJECT_USER,
			},
		},
	},
	{
		Name: string(storage.BootstrapVotersRoleBinding),
		Role: string(storage.VotersRole),
		Subjects: []*v1.Subject{
			{
				Name: string(storage.VotersGroup),
				Type: v1.SubjectType_SUBJECT_GROUP,
			},
		},
	},
}

var groupSeeds = []*v1.Group{
	{
		Name: string(storage.VotersGroup),
		Subjects: []*v1.Subject{
			{
				Name: rbacTestAdmin,
				Type: v1.SubjectType_SUBJECT_NODE,
			},
		},
	},
}
