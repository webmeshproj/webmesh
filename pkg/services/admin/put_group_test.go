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
)

func TestPutGroup(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)

	tt := []testCase[v1.Group]{
		{
			name: "no group name",
			code: codes.InvalidArgument,
			req: &v1.Group{
				Name: "",
				Subjects: []*v1.Subject{
					{
						Type: v1.SubjectType_SUBJECT_ALL,
						Name: "*",
					},
				},
			},
		},
		{
			name: "no subjects",
			code: codes.InvalidArgument,
			req: &v1.Group{
				Name:     "foo",
				Subjects: []*v1.Subject{},
			},
		},
		{
			name: "invalid subject name",
			code: codes.InvalidArgument,
			req: &v1.Group{
				Name: "foo",
				Subjects: []*v1.Subject{
					{
						Type: v1.SubjectType_SUBJECT_ALL,
						Name: "foo,bax",
					},
				},
			},
		},
		{
			name: "invalid subject type",
			code: codes.InvalidArgument,
			req: &v1.Group{
				Name: "foo",
				Subjects: []*v1.Subject{
					{
						Type: -1,
						Name: "foo",
					},
				},
			},
		},
		{
			name: "squash all subjects",
			code: codes.OK,
			req: &v1.Group{
				Name: "foo",
				Subjects: []*v1.Subject{
					{
						Name: "*",
						Type: v1.SubjectType_SUBJECT_ALL,
					},
					{
						Name: "baz",
						Type: v1.SubjectType_SUBJECT_USER,
					},
				},
			},
			tval: func(t *testing.T) {
				rb, err := server.GetGroup(context.Background(), &v1.Group{Name: "foo"})
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
			name: "valid group",
			code: codes.OK,
			req: &v1.Group{
				Name: "foo",
				Subjects: []*v1.Subject{
					{
						Name: "baz",
						Type: v1.SubjectType_SUBJECT_USER,
					},
				},
			},
			tval: func(t *testing.T) {
				rb, err := server.GetGroup(context.Background(), &v1.Group{Name: "foo"})
				if err != nil {
					t.Error("expected no error, got", err)
					return
				}
				if len(rb.Subjects) != 1 {
					t.Error("expected 1 subject, got", len(rb.Subjects))
					return
				}
				if rb.Subjects[0].Name != "baz" {
					t.Error("expected subject name to be 'baz', got", rb.Subjects[0].Name)
					return
				}
				if rb.Subjects[0].Type != v1.SubjectType_SUBJECT_USER {
					t.Error("expected subject type to be 'user', got", rb.Subjects[0].Type)
					return
				}
			},
		},
	}

	runTestCases(t, tt, server.PutGroup)
}
