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

package node

import (
	"io"
	"net"
	"strconv"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/node/pkg/net/datachannels"
	"github.com/webmeshproj/node/pkg/services/rbac"
)

var canNegDataChannelAction = rbac.Actions{
	{
		Verb:     v1.RuleVerb_VERB_PUT,
		Resource: v1.RuleResource_RESOURCE_DATA_CHANNELS,
	},
}

func (s *Server) NegotiateDataChannel(stream v1.Node_NegotiateDataChannelServer) error {
	allowed, err := s.rbacEval.Evaluate(stream.Context(), canNegDataChannelAction)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to evaluate data channel permissions: %v", err)
	}
	if !allowed {
		s.log.Warn("caller not allowed to create data channels")
		return status.Error(codes.PermissionDenied, "not allowed")
	}
	// Pull the initial request from the stream
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	log := s.log.With(slog.Any("request", req))
	// TODO: We trust what the other node is sending for now, but we could save
	// some errors by doing some extra validation first.
	var conn datachannels.ServerChannel
	if req.GetPort() == 0 && req.GetProto() == "udp" {
		log.Info("creating WireGuard proxy connection")
		// Lookup our WireGuard port.
		port, err := s.store.WireGuard().ListenPort()
		if err != nil {
			return status.Errorf(codes.Internal, "failed to get WireGuard listen port: %v", err)
		}
		conn, err = datachannels.NewWireGuardProxyServer(stream.Context(), req.GetStunServers(), uint16(port))
		if err != nil {
			return err
		}
	} else {
		log.Info("creating standard webrtc peer connection")
		conn, err = datachannels.NewServerPeerConnection(&datachannels.OfferOptions{
			Proto:       req.GetProto(),
			SrcAddress:  req.GetSrc(),
			DstAddress:  net.JoinHostPort(req.GetDst(), strconv.Itoa(int(req.GetPort()))),
			STUNServers: req.GetStunServers(),
		})
		if err != nil {
			return err
		}
	}
	go func() {
		<-conn.Closed()
		log.Info("webrtc connection closed")
	}()
	// Send the offer back to the other node
	log.Info("sending offer to other node")
	err = stream.Send(&v1.DataChannelNegotiation{
		Offer: conn.Offer(),
	})
	if err != nil {
		defer conn.Close()
		return err
	}
	// Wait for the answer from the other node
	resp, err := stream.Recv()
	if err != nil {
		defer conn.Close()
		return err
	}
	log.Info("answering offer from other node")
	err = conn.AnswerOffer(resp.GetAnswer())
	if err != nil {
		defer conn.Close()
		return err
	}
	// Handle ICE negotiation
	go func() {
		for candidate := range conn.Candidates() {
			if candidate == "" {
				continue
			}
			log.Info("sending ICE candidate", slog.String("candidate", candidate))
			err := stream.Send(&v1.DataChannelNegotiation{
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
			log.Error("error receiving ICE candidate", slog.String("error", err.Error()))
			return err
		}
		if candidate.GetCandidate() == "" {
			continue
		}
		log.Info("received ICE candidate", slog.String("candidate", candidate.GetCandidate()))
		err = conn.AddCandidate(candidate.GetCandidate())
		if err != nil {
			log.Error("error adding ICE candidate", slog.String("error", err.Error()))
			return err
		}
	}
}
