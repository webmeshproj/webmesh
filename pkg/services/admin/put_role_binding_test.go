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

package admin

import (
	"context"
	"testing"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc/codes"

	"github.com/webmeshproj/webmesh/pkg/meshdb/rbac"
)

func TestPutRoleBinding(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)

	// Pre-create a role to use for testing
	_, err := server.PutRole(context.Background(), &v1.Role{
		Name: "test-role",
		Rules: []*v1.Rule{
			{
				Resources: []v1.RuleResource{v1.RuleResource_RESOURCE_ALL},
				Verbs:     []v1.RuleVerb{v1.RuleVerb_VERB_ALL},
			},
		},
	})
	if err != nil {
		t.Fatal("expected no error, got", err)
	}

	tt := []testCase[v1.RoleBinding]{
		{
			name: "no role binding name",
			code: codes.InvalidArgument,
			req:  &v1.RoleBinding{},
		},
		{
			name: "system admin rolebinding",
			code: codes.InvalidArgument,
			req: &v1.RoleBinding{
				Name: rbac.MeshAdminRoleBinding,
			},
		},
		{
			name: "system voters rolebinding",
			code: codes.InvalidArgument,
			req: &v1.RoleBinding{
				Name: rbac.BootstrapVotersRoleBinding,
			},
		},
		{
			name: "no defined role",
			code: codes.InvalidArgument,
			req: &v1.RoleBinding{
				Name: "test-rolebinding",
				Subjects: []*v1.Subject{
					{
						Name: "*",
						Type: v1.SubjectType_SUBJECT_ALL,
					},
				},
			},
		},
		{
			name: "no defined subjects",
			code: codes.InvalidArgument,
			req: &v1.RoleBinding{
				Name:     "test-rolebinding",
				Role:     "test-role",
				Subjects: []*v1.Subject{},
			},
		},
		{
			name: "invalid subjects",
			code: codes.InvalidArgument,
			req: &v1.RoleBinding{
				Name: "test-rolebinding",
				Role: "test-role",
				Subjects: []*v1.Subject{
					{
						Name: "invalid,subject",
						Type: v1.SubjectType_SUBJECT_USER,
					},
				},
			},
		},
		{
			name: "invalid subject type",
			code: codes.InvalidArgument,
			req: &v1.RoleBinding{
				Name: "test-rolebinding",
				Role: "test-role",
				Subjects: []*v1.Subject{
					{
						Name: "subject",
						Type: -1,
					},
				},
			},
		},
		{
			name: "squash all subjects",
			code: codes.OK,
			req: &v1.RoleBinding{
				Name: "test-rolebinding",
				Role: "test-role",
				Subjects: []*v1.Subject{
					{
						Name: "*",
						Type: v1.SubjectType_SUBJECT_ALL,
					},
					{
						Name: "test-subject",
						Type: v1.SubjectType_SUBJECT_USER,
					},
				},
			},
			tval: func(t *testing.T) {
				rb, err := server.GetRoleBinding(context.Background(), &v1.RoleBinding{Name: "test-rolebinding"})
				if err != nil {
					t.Error("expected no error, got", err)
					return
				}
				if len(rb.Subjects) != 1 {
					t.Error("expected 1 subject, got", len(rb.Subjects))
					return
				}
				if rb.Subjects[0].Name != "*" {
					t.Error("expected subject name to be '*', got", rb.Subjects[0].Name)
					return
				}
				if rb.Subjects[0].Type != v1.SubjectType_SUBJECT_ALL {
					t.Error("expected subject type to be 'all', got", rb.Subjects[0].Type)
					return
				}
			},
		},
		{
			name: "valid rolebinding",
			code: codes.OK,
			req: &v1.RoleBinding{
				Name: "test-rolebinding",
				Role: "test-role",
				Subjects: []*v1.Subject{
					{
						Name: "*",
						Type: v1.SubjectType_SUBJECT_ALL,
					},
				},
			},
			tval: func(t *testing.T) {
				rb, err := server.GetRoleBinding(context.Background(), &v1.RoleBinding{Name: "test-rolebinding"})
				if err != nil {
					t.Error("expected no error, got", err)
					return
				}
				if len(rb.Subjects) != 1 {
					t.Error("expected 1 subject, got", len(rb.Subjects))
					return
				}
				if rb.Subjects[0].Name != "*" {
					t.Error("expected subject name to be '*', got", rb.Subjects[0].Name)
					return
				}
				if rb.Subjects[0].Type != v1.SubjectType_SUBJECT_ALL {
					t.Error("expected subject type to be 'all', got", rb.Subjects[0].Type)
					return
				}
			},
		},
	}

	runTestCases(t, tt, server.PutRoleBinding)
}
