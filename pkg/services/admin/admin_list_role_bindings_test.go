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
	"testing"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/node/pkg/context"
)

func TestListRoleBindings(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server, close := newTestServer(ctx, t)
	defer close()

	// There is no empty condition due to system roles created during bootstrap

	// Place a role and roleBinding
	_, err := server.PutRole(ctx, &v1.Role{
		Name: "foo",
		Rules: []*v1.Rule{
			{
				Resources: []v1.RuleResource{v1.RuleResource_RESOURCE_ALL},
				Verbs:     []v1.RuleVerb{v1.RuleVerb_VERB_ALL},
			},
		},
	})
	if err != nil {
		t.Errorf("PutRole() error = %v", err)
		return
	}
	_, err = server.PutRoleBinding(ctx, &v1.RoleBinding{
		Name: "foo",
		Role: "foo",
		Subjects: []*v1.Subject{{
			Type: v1.SubjectType_SUBJECT_ALL,
			Name: "*",
		}},
	})
	if err != nil {
		t.Errorf("PutRoleBinding() error = %v", err)
		return
	}

	// Verify roleBinding is present
	roleBindings, err := server.ListRoleBindings(ctx, nil)
	if err != nil {
		t.Errorf("ListRoleBindings() error = %v", err)
		return
	}

	var rb *v1.RoleBinding
	for _, r := range roleBindings.GetItems() {
		if r.GetName() == "foo" {
			rb = r
			break
		}
	}
	if rb == nil {
		t.Errorf("ListRoleBindings() did not return expected roleBinding")
		return
	}
	if rb.GetName() != "foo" {
		t.Errorf("ListRoleBindings() did not return expected roleBinding name")
	}
	if rb.GetRole() != "foo" {
		t.Errorf("ListRoleBindings() did not return expected roleBinding role")
	}
	if len(rb.GetSubjects()) != 1 {
		t.Errorf("ListRoleBindings() did not return expected roleBinding subjects")
		return
	}
	if rb.GetSubjects()[0].GetType() != v1.SubjectType_SUBJECT_ALL {
		t.Errorf("ListRoleBindings() did not return expected roleBinding subject type")
	}
	if rb.GetSubjects()[0].GetName() != "*" {
		t.Errorf("ListRoleBindings() did not return expected roleBinding subject name")
	}
}
