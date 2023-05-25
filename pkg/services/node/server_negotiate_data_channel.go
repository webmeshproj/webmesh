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

package node

import (
	"io"

	v1 "gitlab.com/webmesh/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"gitlab.com/webmesh/node/pkg/services/datachannels"
)

func (s *Server) NegotiateDataChannel(stream v1.Node_NegotiateDataChannelServer) error {
	// Pull the initial request from the stream
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	log := s.log.With(slog.Any("request", req))
	// TODO: We trust what the other node is sending for now, but we could save
	// some errors by doing some extra validation first. We should also check
	// that the other node is who they say they are.
	log.Info("creating new webrtc peer connection")
	conn, err := datachannels.NewPeerConnection(&datachannels.OfferOptions{
		Proto:       req.GetProto(),
		SrcAddress:  req.GetSrc(),
		DstAddress:  req.GetDst(),
		STUNServers: req.GetStunServers(),
	})
	if err != nil {
		return err
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
