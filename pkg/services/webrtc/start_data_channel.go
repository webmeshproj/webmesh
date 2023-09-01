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

// Package webrtc contains the webmesh WebRTC service.
package webrtc

import (
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/datachannels"
	"github.com/webmeshproj/webmesh/pkg/services/rbac"
)

var canNegDataChannelAction = rbac.Actions{
	{
		Verb:     v1.RuleVerb_VERB_PUT,
		Resource: v1.RuleResource_RESOURCE_DATA_CHANNELS,
	},
}

func (s *Server) StartDataChannel(stream v1.WebRTC_StartDataChannelServer) error {
	// Determine the remote address of the peer.
	var remoteAddr string
	if p, ok := peer.FromContext(stream.Context()); ok {
		remoteAddr = p.Addr.String()
	}
	log := context.LoggerFrom(stream.Context()).With(slog.String("remote_addr", remoteAddr))
	// Pull the initial request from the stream in a goroutine to avoid blocking
	// forever if the client never sends anything.
	ctx, cancel := context.WithTimeout(stream.Context(), 10*time.Second)
	errs := make(chan error, 1)
	req := make(chan *v1.StartDataChannelRequest, 1)
	go func() {
		defer cancel()
		defer close(errs)
		defer close(req)
		r, err := stream.Recv()
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
	log.Info("Received data channel request")
	if r.GetNodeId() == "" {
		log.Error("Request has empty node ID")
		return status.Error(codes.InvalidArgument, "node ID must be provided in request")
	}
	allowed, err := s.rbacEval.Evaluate(stream.Context(), canNegDataChannelAction.For(r.GetNodeId()))
	if err != nil {
		return status.Errorf(codes.Internal, "failed to evaluate data channel permissions: %v", err)
	}
	if !allowed {
		log.Warn("Not allowed to negotiate data channel")
		return status.Error(codes.PermissionDenied, "not allowed")
	}
	// Set defaults.
	if r.GetDst() == "" {
		r.Dst = "127.0.0.1"
	}
	if r.GetProto() == "" {
		r.Proto = "tcp"
	}
	if r.GetPort() > 65535 {
		log.Error("Request has invalid port")
		return status.Error(codes.InvalidArgument, "invalid port provided in request")
	}
	if r.GetPort() == 0 && r.GetProto() != "udp" {
		log.Error("Request has invalid port")
		return status.Error(codes.InvalidArgument, "invalid port provided in request")
	}
	if r.GetNodeId() == s.opts.ID {
		// We are the destination node.
		return s.handleLocalNegotiation(log, stream, r, remoteAddr)
	}
	return s.handleRemoteNegotiation(log, stream, r, remoteAddr)
}

func (s *Server) handleLocalNegotiation(log *slog.Logger, stream v1.WebRTC_StartDataChannelServer, r *v1.StartDataChannelRequest, remoteAddr string) error {
	log.Info("Handling negotiation locally")
	var conn datachannels.ManagedServerChannel
	var err error
	if r.GetProto() == "udp" && r.GetPort() == 0 {
		log.Info("Negotiating WireGuard proxy connection")
		// Lookup our WireGuard port.
		port, err := s.wg.ListenPort()
		if err != nil {
			return status.Errorf(codes.Internal, "failed to get WireGuard listen port: %v", err)
		}
		conn, err = datachannels.NewWireGuardProxyServer(stream.Context(), s.opts.STUNServers, uint16(port))
		if err != nil {
			return err
		}
	} else {
		log.Info("Negotiating standard WebRTC connection")
		conn, err = datachannels.NewPeerConnectionServer(stream.Context(), &datachannels.OfferOptions{
			Proto:       r.GetProto(),
			SrcAddress:  remoteAddr,
			DstAddress:  net.JoinHostPort(r.GetDst(), strconv.Itoa(int(r.GetPort()))),
			STUNServers: s.opts.STUNServers,
		})
		if err != nil {
			return err
		}
	}
	go func() {
		<-conn.Closed()
		log.Info("WebRTC connection closed")
	}()
	log.Debug("Sending offer to client", slog.String("offer", conn.Offer()))
	err = stream.Send(&v1.DataChannelOffer{
		Offer:       conn.Offer(),
		StunServers: s.opts.STUNServers,
	})
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "failed to send offer to client: %s", err.Error())
	}
	log.Debug("Waiting for answer from client")
	ctx, cancel := context.WithTimeout(stream.Context(), 10*time.Second)
	errs := make(chan error, 1)
	req := make(chan *v1.StartDataChannelRequest, 1)
	go func() {
		defer cancel()
		defer close(errs)
		defer close(req)
		r, err := stream.Recv()
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
		return status.Error(codes.InvalidArgument, "answer must be provided in request")
	}
	log.Debug("Received answer from client", slog.String("answer", r.GetAnswer()))
	err = conn.AnswerOffer(r.GetAnswer())
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "failed to answer offer from client: %s", err.Error())
	}
	log.Debug("Starting ICE negotiation")
	go func() {
		for candidate := range conn.Candidates() {
			if candidate == "" {
				continue
			}
			log.Debug("Sending ICE candidate", slog.String("candidate", candidate))
			err := stream.Send(&v1.DataChannelOffer{
				Candidate: candidate,
			})
			if err != nil {
				if status.Code(err) != codes.Canceled {
					return
				}
				log.Error("error sending ICE candidate", slog.String("error", err.Error()))
				return
			}
		}
	}()
	for {
		candidate, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			log.Error("Error receiving ICE candidate", slog.String("error", err.Error()))
			return err
		}
		if candidate.GetCandidate() == "" {
			continue
		}
		log.Debug("Received ICE candidate", slog.String("candidate", candidate.GetCandidate()))
		err = conn.AddCandidate(candidate.GetCandidate())
		if err != nil {
			log.Error("error adding ICE candidate", slog.String("error", err.Error()))
			return err
		}
	}
}

func (s *Server) handleRemoteNegotiation(log *slog.Logger, clientStream v1.WebRTC_StartDataChannelServer, r *v1.StartDataChannelRequest, remoteAddr string) error {
	// Start a negotiation with the peer.
	var tries int
	maxRetries := 5
	log.Info("Negotiating data channel with remote peer")
	var conn *grpc.ClientConn
	var err error
	for tries < maxRetries {
		conn, err = s.opts.NodeDialer.DialNode(clientStream.Context(), r.GetNodeId())
		if err == nil {
			break
		}
		log.Error("Failed to dial node", slog.String("error", err.Error()))
		tries++
		if tries < maxRetries {
			time.Sleep(1 * time.Second)
		}
	}
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "failed to dial node: %s", err.Error())
	}
	defer conn.Close()
	negotiateStream, err := v1.NewNodeClient(conn).NegotiateDataChannel(clientStream.Context())
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "failed to negotiate data channel with peer: %s", err.Error())
	}
	defer func() {
		err := negotiateStream.CloseSend()
		if err != nil {
			log.Error("failed to close negotiation stream", slog.String("error", err.Error()))
		}
	}()
	err = negotiateStream.Send(&v1.DataChannelNegotiation{
		Proto:       r.GetProto(),
		Src:         remoteAddr,
		Dst:         r.GetDst(),
		Port:        r.GetPort(),
		StunServers: s.opts.STUNServers,
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
	log.Debug("Received offer from peer", slog.String("offer", resp.GetOffer()))
	// Forward the offer to the client
	err = clientStream.Send(&v1.DataChannelOffer{
		Offer:       resp.GetOffer(),
		StunServers: s.opts.STUNServers,
	})
	if err != nil {
		return err
	}
	// Pull the answer from the client
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
	log.Debug("Sending answer to peer", slog.String("answer", r.GetAnswer()))
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
			if status.Code(err) != codes.Canceled || err != io.EOF {
				log.Error("Failed to receive candidate from node", slog.String("error", err.Error()))
			}
			return
		}
		if nodeCandidate.GetCandidate() == "" {
			log.Error("Received empty candidate from node")
			return
		}
		log.Debug("Received ICE candidate from node", slog.String("candidate", nodeCandidate.GetCandidate()))
		err = clientStream.Send(&v1.DataChannelOffer{
			Candidate: nodeCandidate.GetCandidate(),
		})
		if err != nil {
			if status.Code(err) != codes.Canceled {
				log.Error("Failed to send candidate to client", slog.String("error", err.Error()))
			}
			return
		}
	}()
	for {
		clientCandidate, err := clientStream.Recv()
		if err != nil {
			if err != io.EOF {
				log.Error("Failed to receive candidate from client", slog.String("error", err.Error()))
				return status.Errorf(codes.Internal, "failed to receive candidate from client: %s", err.Error())
			}
			return nil
		}
		if clientCandidate.GetCandidate() == "" {
			log.Error("Received empty candidate from client")
			return status.Error(codes.InvalidArgument, "received empty candidate from client")
		}
		log.Debug("Received ICE candidate from client", slog.String("candidate", clientCandidate.GetCandidate()))
		err = negotiateStream.Send(&v1.DataChannelNegotiation{
			Candidate: clientCandidate.GetCandidate(),
		})
		if err != nil {
			if status.Code(err) != codes.Canceled {
				log.Error("Failed to ICE send candidate to node", slog.String("error", err.Error()))
				return status.Errorf(codes.Internal, "failed to send candidate to node: %s", err.Error())
			}
			return nil
		}
	}
}
