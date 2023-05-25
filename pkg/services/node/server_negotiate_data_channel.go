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

	"gitlab.com/webmesh/node/pkg/services/node/datachannels"
)

func (s *Server) NegotiateDataChannel(stream v1.Node_NegotiateDataChannelServer) error {
	// Pull the initial request from the stream
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	// TODO: We trust what the other node is sending for now, but we could save
	// some errors by doing some extra validation first. We should also check
	// that the other node is who they say they are.
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
		s.log.Info("data channel closed",
			slog.String("src", req.GetSrc()), slog.String("dst", req.GetDst()))
	}()
	// Send the offer back to the other node
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
			err := stream.Send(&v1.DataChannelNegotiation{
				Candidate: candidate,
			})
			if err != nil {
				if status.Code(err) != codes.Canceled {
					return
				}
				s.log.Error("error sending ICE candidate", slog.String("error", err.Error()))
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
			return err
		}
		if candidate.GetCandidate() == "" {
			continue
		}
		err = conn.AddCandidate(candidate.GetCandidate())
		if err != nil {
			return err
		}
	}
}
