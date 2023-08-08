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

package campfire

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/pion/ice/v2"
	"github.com/pion/stun"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/util"
)

type ICEFire struct {
	agent      *ice.Agent
	ufrag, pwd string
	readyc     chan struct{}
}

func JoinICE(ctx context.Context, opts Options) (*ICEFire, error) {
	ufrag := string(opts.PSK)
	loc, err := Find(opts.PSK, opts.TURNServers)
	if err != nil {
		return nil, fmt.Errorf("failed to find campfire: %w", err)
	}
	pwd := string(loc.Secret)
	log := context.LoggerFrom(ctx).With("protocol", "campfire")
	log.Info("Joining campfire", slog.Any("location", loc))
	uri, err := stun.ParseURI(loc.TURNServer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse turn server URI: %w", err)
	}
	uri.Username = ufrag
	uri.Password = pwd
	ulis, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}
	umux := ice.NewUDPMuxDefault(ice.UDPMuxParams{
		UDPConn: ulis,
	})
	tlis, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}
	tmux := ice.NewTCPMuxDefault(ice.TCPMuxParams{
		Listener: tlis,
	})
	agent, err := ice.NewAgent(&ice.AgentConfig{
		Urls:       []*stun.URI{uri},
		LocalUfrag: ufrag,
		LocalPwd:   pwd,
		NetworkTypes: []ice.NetworkType{
			ice.NetworkTypeUDP4,
			ice.NetworkTypeUDP6,
			ice.NetworkTypeTCP4,
			ice.NetworkTypeTCP6,
		},
		CandidateTypes: []ice.CandidateType{
			ice.CandidateTypeHost,
			ice.CandidateTypeServerReflexive,
			ice.CandidateTypeRelay,
		},
		LoggerFactory:   util.NewSTUNLoggerFactory(log),
		TCPMux:          tmux,
		UDPMux:          umux,
		IncludeLoopback: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create ice agent: %w", err)
	}
	_ = agent.OnConnectionStateChange(func(state ice.ConnectionState) {
		log.Info("ICE connection state changed", slog.Any("state", state))
	})
	_ = agent.OnSelectedCandidatePairChange(func(local, remote ice.Candidate) {
		log.Info("ICE selected candidate pair changed", slog.Any("local", local), slog.Any("remote", remote))
	})
	readyc := make(chan struct{})
	_ = agent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			close(readyc)
			return
		}
		err := agent.AddRemoteCandidate(c)
		if err != nil {
			log.Error("failed to add remote candidate", slog.String("error", err.Error()))
			return
		}
	})
	err = agent.SetRemoteCredentials(ufrag, pwd)
	if err != nil {
		return nil, fmt.Errorf("failed to set remote credentials: %w", err)
	}
	err = agent.GatherCandidates()
	if err != nil {
		return nil, fmt.Errorf("failed to gather candidates: %w", err)
	}
	return &ICEFire{agent, ufrag, pwd, readyc}, nil
}

func (cf *ICEFire) Close() error {
	return cf.agent.Close()
}

func (cf *ICEFire) Ready() <-chan struct{} {
	return cf.readyc
}

func (cf *ICEFire) Dial(ctx context.Context) (*ice.Conn, error) {
	log := context.LoggerFrom(ctx).With("protocol", "campfire")
	log.Info("Dialing campfire")
	conn, err := cf.agent.Dial(ctx, cf.ufrag, cf.pwd)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	return conn, nil
}

func (cf *ICEFire) Accept(ctx context.Context) (*ice.Conn, error) {
	log := context.LoggerFrom(ctx).With("protocol", "campfire")
	log.Info("Accepting campfire")
	conn, err := cf.agent.Accept(ctx, cf.ufrag, cf.pwd)
	if err != nil {
		return nil, fmt.Errorf("failed to accept: %w", err)
	}
	return conn, nil
}
