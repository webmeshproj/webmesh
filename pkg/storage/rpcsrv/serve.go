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

// Package rpcsrv contains utilities for serving mesh databases over RPC.
package rpcsrv

import (
	"io"

	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

// QueryClient is the interface for a storage query client.
type QueryClient interface {
	// The underlying gRPC stream.
	grpc.ClientStream
	// Send sends a query result to the plugin.
	Send(*v1.QueryResponse) error
	// Recv receives a query request from the plugin.
	Recv() (*v1.QueryRequest, error)
}

// Serve serves database operations over a plugin query stream.
func Serve(ctx context.Context, db storage.Provider, cli QueryClient) error {
	log := context.LoggerFrom(ctx)
	defer func() {
		err := cli.CloseSend()
		if err != nil {
			log.Error("Error closing query stream", "error", err)
		}
	}()
	for {
		query, err := cli.Recv()
		if err != nil {
			if err == io.EOF {
				log.Debug("Query stream closed cleanly")
				return nil
			}
			// TODO: restart the stream?
			log.Error("Error receiving query", "error", err)
			return err
		}
		log.Debug("Handling query request",
			"command", query.GetCommand().String(),
			"type", query.GetType().String(),
			"query", query.GetQuery(),
		)
		resp, err := ServeQuery(ctx, db, query)
		if err != nil {
			log.Error("Error handling query", "error", err)
		}
		// We send the response back no matter what.
		err = cli.Send(resp)
		if err != nil {
			log.Error("Error sending query response", "error", err)
			return err
		}
	}
}
