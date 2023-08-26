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

package storage

import (
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) Query(req *v1.QueryRequest, stream v1.Storage_QueryServer) error {
	if !s.store.Raft().IsVoter() && !s.store.Raft().IsObserver() {
		// In theory - non-raft members shouldn't even expose the Node service.
		return status.Error(codes.Unavailable, "node not available to query")
	}
	switch req.GetCommand() {
	case v1.QueryRequest_GET:
		var result v1.QueryResponse
		result.Key = req.GetQuery()
		val, err := s.store.Storage().Get(stream.Context(), req.GetQuery())
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Value = []string{val}
		}
		err = stream.Send(&result)
		if err != nil {
			return err
		}
	case v1.QueryRequest_LIST:
		var result v1.QueryResponse
		result.Key = req.GetQuery()
		vals, err := s.store.Storage().List(stream.Context(), req.GetQuery())
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Value = vals
		}
		err = stream.Send(&result)
		if err != nil {
			return err
		}
	case v1.QueryRequest_ITER:
		err := s.store.Storage().IterPrefix(stream.Context(), req.GetQuery(), func(key, value string) error {
			var result v1.QueryResponse
			result.Key = key
			result.Value = []string{value}
			return stream.Send(&result)
		})
		if err != nil {
			return err
		}
		var result v1.QueryResponse
		result.Error = "EOF"
		return stream.Send(&result)
	}
	return status.Errorf(codes.Unimplemented, "unknown query command: %v", req.GetCommand())
}
