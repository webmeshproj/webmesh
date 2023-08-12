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

package mesh

import (
	"io"
	"log/slog"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	"github.com/webmeshproj/webmesh/pkg/campfire"
	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/services/leaderproxy"
)

func (s *meshStore) waitByCampfire() {
	log := s.log.With("protocol", "campfire")
	cf, err := campfire.Wait(context.Background(), campfire.Options{
		PSK:         []byte(s.opts.Mesh.WaitCampfirePSK),
		TURNServers: s.opts.Mesh.WaitCampfireTURNServers,
	})
	if err != nil {
		log.Error("Failed to wait by campfire, will try again in 15 seconds", "error", err.Error())
		// TODO: Make this configurable
		time.Sleep(15 * time.Second)
		go s.waitByCampfire()
		return
	}
	defer cf.Close()
	log.Info("Announced ourselves at the campfire")
	go func() {
		for {
			conn, err := cf.Accept()
			if err != nil {
				if err == campfire.ErrClosed {
					return
				}
				log.Error("Failed to accept campfire connection", "error", err.Error())
			}
			go s.handleIncomingCampfireConn(log, conn)
		}
	}()
	for {
		select {
		case <-s.closec:
			return
		case err := <-cf.Errors():
			log.Error("Campfire error", "error", err.Error())
		case <-cf.Expired():
			log.Info("Campfire connection expired, reconnecting")
			time.Sleep(3 * time.Second)
			go s.waitByCampfire()
		}
	}
}

func (s *meshStore) handleIncomingCampfireConn(log *slog.Logger, conn io.ReadWriteCloser) {
	defer conn.Close()
	log.Info("Handling incoming campfire connection")
	// Read a join request off the wire
	var req v1.JoinRequest
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		log.Error("Failed to read join request", "error", err.Error())
		return
	}
	if err := proto.Unmarshal(buf[:n], &req); err != nil {
		log.Error("Failed to unmarshal join request", "error", err.Error())
		return
	}
	// In this context we are a proxy for the connection. No authentication is handled
	// on the campfire protocol yet, but we will add the leaderproxy metadata to the
	// request so that the leader can authenticate the request in the future.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second) // TODO: Make this configurable
	defer cancel()
	c, err := s.DialLeader(ctx)
	if err != nil {
		log.Error("Failed to dial leader", "error", err.Error())
		return
	}
	defer c.Close()
	ctx = metadata.AppendToOutgoingContext(ctx, leaderproxy.ProxiedFromMeta, s.ID())
	// Here is where we'd authenticate the request for the leader
	ctx = metadata.AppendToOutgoingContext(ctx, leaderproxy.ProxiedForMeta, req.GetId())
	// Send the join request to the leader
	resp, err := v1.NewNodeClient(c).Join(ctx, &req)
	// We are writing either the response or the error to the connection
	if err != nil {
		log.Warn("Failed to proxy join to leader", "error", err.Error())
		if _, err := conn.Write([]byte(err.Error())); err != nil {
			log.Error("Failed to write error to connection", "error", err.Error())
		}
		return
	}
	// Marshal the request back to protobuf
	buf, err = proto.Marshal(resp)
	if err != nil {
		log.Error("Failed to marshal join response", "error", err.Error())
		return
	}
	// Write the response to the connection
	if _, err := conn.Write(buf); err != nil {
		log.Error("Failed to write response to connection", "error", err.Error())
		return
	}
}
