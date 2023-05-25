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

// Package webrtc contains the webmesh WebRTC service.
package webrtc

import (
	"context"
	"io"
	"time"

	v1 "gitlab.com/webmesh/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func (s *Server) StartDataChannel(clientStream v1.WebRTC_StartDataChannelServer) error {
	// Determine the remote address of the peer.
	var remoteAddr string
	if p, ok := peer.FromContext(clientStream.Context()); ok {
		remoteAddr = p.Addr.String()
	}

	log := s.log.With(slog.String("remote_addr", remoteAddr))

	// Pull the initial request from the stream in a goroutine to avoid blocking
	// forever if the client never sends anything.
	ctx, cancel := context.WithTimeout(clientStream.Context(), 10*time.Second)
	errs := make(chan error, 1)
	req := make(chan *v1.StartDataChannelRequest, 1)
	go func() {
		defer cancel()
		defer close(errs)
		defer close(req)
		r, err := clientStream.Recv()
		if err != nil {
			errs <- err
			return
		}
		req <- r
	}()
	var r *v1.StartDataChannelRequest
	select {
	case <-ctx.Done():
		return status.Error(codes.DeadlineExceeded, "timed out waiting for initial request")
	case err := <-errs:
		return err
	case r = <-req:
	}
	log = log.With(slog.Any("request", r))
	log.Info("received data channel request")
	if r.GetNodeId() == "" {
		log.Error("request has empty node ID")
		return status.Error(codes.InvalidArgument, "node ID must be provided in request")
	}
	if r.GetPort() == 0 || r.GetPort() > 65535 {
		log.Error("request has invalid port")
		return status.Error(codes.InvalidArgument, "invalid port provided in request")
	}
	// Set defaults.
	if r.GetDst() == "" {
		r.Dst = "127.0.0.1"
	}
	if r.GetProto() == "" {
		r.Proto = "tcp"
	}

	// Start a negotiation with the peer.
	log.Info("negotiating data channel with peer")
	client, closer, err := s.newPeerClient(clientStream.Context(), r.GetNodeId())
	if err != nil {
		return err
	}
	defer closer.Close()
	negotiateStream, err := client.NegotiateDataChannel(clientStream.Context())
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "failed to negotiate data channel with peer: %s", err.Error())
	}
	defer func() {
		err := negotiateStream.CloseSend()
		if err != nil {
			s.log.Error("failed to close negotiation stream", slog.String("error", err.Error()))
		}
	}()
	err = negotiateStream.Send(&v1.DataChannelNegotiation{
		Proto:       r.GetProto(),
		Src:         remoteAddr,
		Dst:         r.GetDst(),
		Port:        r.GetPort(),
		StunServers: s.stunServers,
	})
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "failed to send negotiation request to peer: %s", err.Error())
	}
	// Pull the offer from the peer
	resp, err := negotiateStream.Recv()
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "failed to receive offer from peer: %s", err.Error())
	}
	if resp.GetOffer() == "" {
		return status.Error(codes.FailedPrecondition, "peer did not send an offer")
	}
	log.Info("received offer from peer", slog.String("offer", resp.GetOffer()))
	// Forward the offer to the client
	err = clientStream.Send(&v1.DataChannelOffer{
		Offer:       resp.GetOffer(),
		StunServers: s.stunServers,
	})
	if err != nil {
		return err
	}
	// Pull the answer from the client
	ctx, cancel = context.WithTimeout(clientStream.Context(), 10*time.Second)
	errs = make(chan error, 1)
	req = make(chan *v1.StartDataChannelRequest, 1)
	go func() {
		defer cancel()
		defer close(errs)
		defer close(req)
		r, err := clientStream.Recv()
		if err != nil {
			errs <- err
			return
		}
		req <- r
	}()
	select {
	case <-ctx.Done():
		return status.Error(codes.DeadlineExceeded, "timed out waiting for answer from client")
	case err := <-errs:
		return err
	case r = <-req:
	}
	if r.GetAnswer() == "" {
		return status.Error(codes.InvalidArgument, "client did not send an answer")
	}
	// Send the answer to the peer
	log.Info("sending answer to peer", slog.String("answer", r.GetAnswer()))
	err = negotiateStream.Send(&v1.DataChannelNegotiation{
		Answer: r.GetAnswer(),
	})
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "failed to send answer to peer: %s", err.Error())
	}
	// Optionally hold the stream open for ICE candidate exchange.
	go func() {
		nodeCandidate, err := negotiateStream.Recv()
		if err != nil {
			if err != io.EOF {
				log.Error("failed to receive candidate from node", slog.String("error", err.Error()))
			}
			return
		}
		if nodeCandidate.GetCandidate() == "" {
			s.log.Error("received empty candidate from node")
			return
		}
		log.Info("received candidate from node", slog.String("candidate", nodeCandidate.GetCandidate()))
		err = clientStream.Send(&v1.DataChannelOffer{
			Candidate: nodeCandidate.GetCandidate(),
		})
		if err != nil {
			if status.Code(err) != codes.Canceled {
				log.Error("failed to send candidate to client", slog.String("error", err.Error()))
			}
			return
		}
	}()
	for {
		clientCandidate, err := clientStream.Recv()
		if err != nil {
			if err != io.EOF {
				log.Error("failed to receive candidate from client", slog.String("error", err.Error()))
				return status.Errorf(codes.Internal, "failed to receive candidate from client: %s", err.Error())
			}
			return nil
		}
		if clientCandidate.GetCandidate() == "" {
			log.Error("received empty candidate from client")
			return status.Error(codes.InvalidArgument, "received empty candidate from client")
		}
		log.Info("received candidate from client", slog.String("candidate", clientCandidate.GetCandidate()))
		err = negotiateStream.Send(&v1.DataChannelNegotiation{
			Candidate: clientCandidate.GetCandidate(),
		})
		if err != nil {
			if status.Code(err) != codes.Canceled {
				log.Error("failed to send candidate to node", slog.String("error", err.Error()))
				return status.Errorf(codes.Internal, "failed to send candidate to node: %s", err.Error())
			}
			return nil
		}
	}
}

func (s *Server) newPeerClient(ctx context.Context, id string) (v1.NodeClient, io.Closer, error) {
	addr, err := s.meshstate.GetNodePrivateRPCAddress(ctx, id)
	if err != nil {
		s.log.Error("failed to get peer address", slog.String("error", err.Error()))
		return nil, nil, status.Error(codes.NotFound, "failed to get peer address")
	}
	var creds credentials.TransportCredentials
	if s.tlsConfig == nil {
		creds = insecure.NewCredentials()
	} else {
		creds = credentials.NewTLS(s.tlsConfig)
	}
	conn, err := grpc.DialContext(ctx, addr.String(), grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, nil, status.Errorf(codes.FailedPrecondition, "could not connect to node %s: %s", id, err.Error())
	}
	return v1.NewNodeClient(conn), conn, nil
}
