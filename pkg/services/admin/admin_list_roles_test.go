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
)

func TestListRoles(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server, close := newTestServer(ctx, t)
	defer close()

	// There is no empty condition due to system roles created during bootstrap

	// Place a role
	_, err := server.PutRole(ctx, &v1.Role{
		Name: "foo",
		Rules: []*v1.Rule{{
			Resources: []v1.RuleResource{v1.RuleResource_RESOURCE_ALL},
			Verbs:     []v1.RuleVerb{v1.RuleVerb_VERB_ALL},
		}},
	})
	if err != nil {
		t.Errorf("PutRole() error = %v", err)
		return
	}

	// Verify role is present
	roles, err := server.ListRoles(ctx, nil)
	if err != nil {
		t.Errorf("ListRoles() error = %v", err)
		return
	}

	// Role should be present
	var role *v1.Role
	for _, r := range roles.GetItems() {
		if r.GetName() == "foo" {
			role = r
			break
		}
	}
	if role == nil {
		t.Errorf("ListRoles() expected role 'foo' present, got %v", roles.GetItems())
		return
	}
	if len(role.GetRules()) != 1 {
		t.Errorf("ListRoles() expected 1 rule, got %v", roles.GetItems()[0].GetRules())
		return
	}
	if len(role.GetRules()[0].GetResources()) != 1 {
		t.Errorf("ListRoles() expected 1 resource, got %v", roles.GetItems()[0].GetRules()[0].GetResources())
		return
	}
	if role.GetRules()[0].GetResources()[0] != v1.RuleResource_RESOURCE_ALL {
		t.Errorf("ListRoles() expected resource 'all', got %v", roles.GetItems()[0].GetRules()[0].GetResources()[0])
		return
	}
	if len(role.GetRules()[0].GetVerbs()) != 1 {
		t.Errorf("ListRoles() expected 1 verb, got %v", roles.GetItems()[0].GetRules()[0].GetVerbs())
		return
	}
	if role.GetRules()[0].GetVerbs()[0] != v1.RuleVerb_VERB_ALL {
		t.Errorf("ListRoles() expected verb 'all', got %v", roles.GetItems()[0].GetRules()[0].GetVerbs()[0])
		return
	}
}
