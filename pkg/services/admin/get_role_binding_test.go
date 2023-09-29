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
	"google.golang.org/grpc/codes"

	"github.com/webmeshproj/webmesh/pkg/storage/meshdb/rbac"
)

func TestGetRoleBinding(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)

	tc := []testCase[v1.RoleBinding]{
		{
			name: "no rolebinding name",
			code: codes.InvalidArgument,
			req:  &v1.RoleBinding{},
		},
		{
			name: "non-existent rolebinding",
			req:  &v1.RoleBinding{Name: "non-existent-rolebinding"},
			code: codes.NotFound,
		},
		{
			name: "existing system rolebinding",
			req:  &v1.RoleBinding{Name: string(rbac.MeshAdminRoleBinding)},
			code: codes.OK,
		},
	}

	runTestCases(t, tc, server.GetRoleBinding)
}
