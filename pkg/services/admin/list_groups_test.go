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

	v1 "github.com/webmeshproj/api/go/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
)

func TestListGroups(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server := newTestServer(t)

	// No empty condition

	// Place a group
	_, err := server.PutGroup(ctx, &v1.Group{
		Name: "foo",
		Subjects: []*v1.Subject{
			{
				Name: "bar",
				Type: v1.SubjectType_SUBJECT_USER,
			},
		},
	})
	if err != nil {
		t.Errorf("PutGroup() error = %v", err)
		return
	}

	// Verify group is present
	groups, err := server.ListGroups(ctx, nil)
	if err != nil {
		t.Errorf("ListGroups() error = %v", err)
		return
	}

	var group *v1.Group
	for _, g := range groups.GetItems() {
		if g.Name == "foo" {
			group = g
			break
		}
	}
	if group == nil {
		t.Errorf("ListGroups() did not return expected group")
	}
	if len(group.GetSubjects()) != 1 {
		t.Errorf("ListGroups() did not return expected group subjects")
		return
	}
	sub := group.GetSubjects()[0]
	if sub.Name != "bar" {
		t.Errorf("ListGroups() did not return expected group subject name")
	}
	if sub.Type != v1.SubjectType_SUBJECT_USER {
		t.Errorf("ListGroups() did not return expected group subject type")
	}
}
