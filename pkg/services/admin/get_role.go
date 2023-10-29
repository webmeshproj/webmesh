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

// Package admin provides the admin gRPC server.
package admin

import (
	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
)

func (s *Server) GetRole(ctx context.Context, role *v1.Role) (*v1.Role, error) {
	if role.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	out, err := s.db.RBAC().GetRole(ctx, role.GetName())
	if err != nil {
		if errors.IsRoleNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "role %q not found", role.GetName())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return out.Proto(), nil
}
