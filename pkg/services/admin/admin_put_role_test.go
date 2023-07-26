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

	"github.com/webmeshproj/node/pkg/meshdb/rbac"
)

func TestPutRole(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server := newTestServer(t)

	tt := []testCase[v1.Role]{
		{
			name: "no role name",
			code: codes.InvalidArgument,
			req:  &v1.Role{},
		},
		{
			name: "system admin role",
			code: codes.InvalidArgument,
			req: &v1.Role{
				Name: rbac.MeshAdminRole,
			},
		},
		{
			name: "system voters role",
			code: codes.InvalidArgument,
			req: &v1.Role{
				Name: rbac.VotersRole,
			},
		},
		{
			name: "no defined rules",
			code: codes.InvalidArgument,
			req: &v1.Role{
				Name: "test-role",
			},
		},
		{
			name: "no defined verbs",
			code: codes.InvalidArgument,
			req: &v1.Role{
				Name: "test-role",
				Rules: []*v1.Rule{
					{
						Resources: []v1.RuleResource{v1.RuleResource_RESOURCE_ALL},
						Verbs:     []v1.RuleVerb{},
					},
				},
			},
		},
		{
			name: "no defined resources",
			code: codes.InvalidArgument,
			req: &v1.Role{
				Name: "test-role",
				Rules: []*v1.Rule{
					{
						Resources: []v1.RuleResource{},
						Verbs:     []v1.RuleVerb{v1.RuleVerb_VERB_ALL},
					},
				},
			},
		},
		{
			name: "invalid verb",
			code: codes.InvalidArgument,
			req: &v1.Role{
				Name: "test-role",
				Rules: []*v1.Rule{
					{
						Resources: []v1.RuleResource{v1.RuleResource_RESOURCE_ALL},
						Verbs:     []v1.RuleVerb{-1},
					},
				},
			},
		},
		{
			name: "invalid resource",
			code: codes.InvalidArgument,
			req: &v1.Role{
				Name: "test-role",
				Rules: []*v1.Rule{
					{
						Resources: []v1.RuleResource{-1},
						Verbs:     []v1.RuleVerb{v1.RuleVerb_VERB_ALL},
					},
				},
			},
		},
		{
			name: "squashed wildcard verbs",
			code: codes.OK,
			req: &v1.Role{
				Name: "test-put-wildcard-verbs",
				Rules: []*v1.Rule{
					{
						Resources: []v1.RuleResource{v1.RuleResource_RESOURCE_ALL},
						Verbs:     []v1.RuleVerb{v1.RuleVerb_VERB_ALL, v1.RuleVerb_VERB_GET},
					},
				},
			},
			tval: func(t *testing.T) {
				role, err := server.GetRole(ctx, &v1.Role{Name: "test-put-wildcard-verbs"})
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if len(role.Rules) != 1 {
					t.Errorf("expected 1 rule, got: %v", len(role.Rules))
					return
				}
				if len(role.Rules[0].Verbs) != 1 {
					t.Errorf("expected 1 verb, got: %v", len(role.Rules[0].Verbs))
					return
				}
				if role.Rules[0].Verbs[0] != v1.RuleVerb_VERB_ALL {
					t.Errorf("expected verb: %v, got: %v", v1.RuleVerb_VERB_ALL, role.Rules[0].Verbs[0])
					return
				}
			},
		},
		{
			name: "squashed wildcard resources",
			code: codes.OK,
			req: &v1.Role{
				Name: "test-put-wildcard-resources",
				Rules: []*v1.Rule{
					{
						Resources: []v1.RuleResource{v1.RuleResource_RESOURCE_ALL, v1.RuleResource_RESOURCE_NETWORK_ACLS},
						Verbs:     []v1.RuleVerb{v1.RuleVerb_VERB_ALL},
					},
				},
			},
			tval: func(t *testing.T) {
				role, err := server.GetRole(ctx, &v1.Role{Name: "test-put-wildcard-resources"})
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if len(role.Rules) != 1 {
					t.Errorf("expected 1 rule, got: %v", len(role.Rules))
					return
				}
				if len(role.Rules[0].Resources) != 1 {
					t.Errorf("expected 1 resource, got: %v", len(role.Rules[0].Resources))
					return
				}
				if role.Rules[0].Resources[0] != v1.RuleResource_RESOURCE_ALL {
					t.Errorf("expected resource: %v, got: %v", v1.RuleResource_RESOURCE_ALL, role.Rules[0].Resources[0])
					return
				}
			},
		},
		{
			name: "valid role",
			code: codes.OK,
			req: &v1.Role{
				Name: "test-put-valid-role",
				Rules: []*v1.Rule{
					{
						Resources: []v1.RuleResource{v1.RuleResource_RESOURCE_NETWORK_ACLS, v1.RuleResource_RESOURCE_ROLES},
						Verbs:     []v1.RuleVerb{v1.RuleVerb_VERB_GET, v1.RuleVerb_VERB_PUT},
					},
				},
			},
			tval: func(t *testing.T) {
				role, err := server.GetRole(ctx, &v1.Role{Name: "test-put-valid-role"})
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if len(role.Rules) != 1 {
					t.Errorf("expected 1 rule, got: %v", len(role.Rules))
					return
				}
				if len(role.Rules[0].Resources) != 2 {
					t.Errorf("expected 2 resources, got: %v", len(role.Rules[0].Resources))
					return
				}
				if role.Rules[0].Resources[0] != v1.RuleResource_RESOURCE_NETWORK_ACLS {
					t.Errorf("expected resource: %v, got: %v", v1.RuleResource_RESOURCE_NETWORK_ACLS, role.Rules[0].Resources[0])
				}
				if role.Rules[0].Resources[1] != v1.RuleResource_RESOURCE_ROLES {
					t.Errorf("expected resource: %v, got: %v", v1.RuleResource_RESOURCE_ROLES, role.Rules[0].Resources[1])
				}
				if len(role.Rules[0].Verbs) != 2 {
					t.Errorf("expected 2 verbs, got: %v", len(role.Rules[0].Verbs))
					return
				}
				if role.Rules[0].Verbs[0] != v1.RuleVerb_VERB_GET {
					t.Errorf("expected verb: %v, got: %v", v1.RuleVerb_VERB_GET, role.Rules[0].Verbs[0])
				}
				if role.Rules[0].Verbs[1] != v1.RuleVerb_VERB_PUT {
					t.Errorf("expected verb: %v, got: %v", v1.RuleVerb_VERB_PUT, role.Rules[0].Verbs[1])
				}
			},
		},
	}

	runTestCases(t, tt, server.PutRole)
}
