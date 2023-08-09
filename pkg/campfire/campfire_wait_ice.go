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
	"io"

	"github.com/pion/ice/v2"
	"github.com/pion/stun"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/util"
)

func WaitICE(ctx context.Context, opts Options) (CampFire, error) {
	log := context.LoggerFrom(ctx).With("protocol", "campfire")
	location, err := Find(opts.PSK, opts.TURNServers)
	if err != nil {
		return nil, fmt.Errorf("find campfire: %w", err)
	}
	uri, err := stun.ParseURI(location.TURNServer)
	if err != nil {
		return nil, fmt.Errorf("parse turn server uri: %w", err)
	}
	uri.Username = "-"
	uri.Password = location.LocalPwd()
	agent, err := ice.NewAgent(&ice.AgentConfig{
		Urls:       []*stun.URI{uri},
		LocalUfrag: location.LocalUfrag(),
		LocalPwd:   location.LocalPwd(),
		NetworkTypes: []ice.NetworkType{
			ice.NetworkTypeTCP4,
			ice.NetworkTypeTCP6,
			ice.NetworkTypeUDP4,
			ice.NetworkTypeUDP6,
		},
		CandidateTypes: []ice.CandidateType{
			ice.CandidateTypeRelay,
		},
		LoggerFactory:      util.NewSTUNLoggerFactory(log),
		InsecureSkipVerify: false,
		IncludeLoopback:    true,
	})
	if err != nil {
		return nil, fmt.Errorf("create ice agent: %w", err)
	}
	readyc := make(chan struct{})
	err = agent.OnCandidate(func(candidate ice.Candidate) {
		if candidate == nil {
			return
		}
		log.Info("ice candidate", "candidate", candidate.String())
		err = agent.AddRemoteCandidate(candidate)
		if err != nil {
			log.Error("add remote candidate", "error", err)
		}
	})
	if err != nil {
		return nil, fmt.Errorf("on candidate: %w", err)
	}
	err = agent.OnConnectionStateChange(func(state ice.ConnectionState) {
		log.Info("ice connection state changed", "state", state.String())
		if state == ice.ConnectionStateConnected {
			close(readyc)
		}
	})
	if err != nil {
		return nil, fmt.Errorf("on connection state change: %w", err)
	}
	err = agent.OnSelectedCandidatePairChange(func(local, remote ice.Candidate) {
		log.Info("ice selected candidate pair changed", "local", local.String(), "remote", remote.String())
	})
	err = agent.GatherCandidates()
	if err != nil {
		return nil, fmt.Errorf("gather candidates: %w", err)
	}
	errc := make(chan error, 1)
	acceptc := make(chan io.ReadWriteCloser, 1)
	go func() {
		log.Info("waiting for ice connection")
		for {
			conn, err := agent.Accept(ctx, location.RemoteUfrag(), location.RemotePwd())
			if err != nil {
				errc <- fmt.Errorf("accept ice connection: %w", err)
				return
			}
			acceptc <- conn
		}
	}()
	return &offlineICECampFire{
		agent:   agent,
		errc:    errc,
		readyc:  readyc,
		acceptc: acceptc,
		closec:  make(chan struct{}),
	}, nil
}

type offlineICECampFire struct {
	agent   *ice.Agent
	errc    chan error
	readyc  chan struct{}
	acceptc chan io.ReadWriteCloser
	closec  chan struct{}
}

// Accept returns a connection to a peer.
func (o *offlineICECampFire) Accept() (io.ReadWriteCloser, error) {
	select {
	case <-o.closec:
		return nil, ErrClosed
	case <-o.readyc:
	}
	select {
	case <-o.closec:
		return nil, ErrClosed
	case conn := <-o.acceptc:
		return conn, nil
	}
}

// Close closes the camp fire.
func (o *offlineICECampFire) Close() error {
	select {
	case <-o.closec:
		return ErrClosed
	default:
	}
	close(o.closec)
	return o.agent.Close()
}

// Errors returns a channel of errors.
func (o *offlineICECampFire) Errors() <-chan error {
	return o.errc
}

// Ready returns a channel that is closed when the camp fire is ready.
func (o *offlineICECampFire) Ready() <-chan struct{} {
	return o.readyc
}
