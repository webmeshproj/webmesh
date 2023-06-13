/*
Copyright 2023.

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

// Package store provides raft consensus and data storage for webmesh nodes.
package store

import (
	"context"
	"fmt"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// leaveCluster attempts to remove this node from the cluster. The node must
// have already relinquished leadership before calling this method.
func (s *store) leaveCluster(ctx context.Context) error {
	s.log.Info("leaving cluster")
	addr, err := s.LeaderRPCAddr(ctx)
	if err != nil {
		return fmt.Errorf("get leader address: %w", err)
	}
	var creds credentials.TransportCredentials
	if s.opts.TLS.Insecure {
		creds = insecure.NewCredentials()
	} else {
		creds = credentials.NewTLS(s.tlsConfig)
	}
	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("dial leader: %w", err)
	}
	defer conn.Close()
	client := v1.NewNodeClient(conn)
	_, err = client.Leave(ctx, &v1.LeaveRequest{
		Id: s.ID(),
	})
	return err
}
