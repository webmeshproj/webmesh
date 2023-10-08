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

package config

import (
	"testing"
	"time"

	"github.com/spf13/pflag"
)

func TestDiscoveryConfigValidate(t *testing.T) {
	t.Parallel()
	defaults := NewDiscoveryOptions("", false)
	tc := []struct {
		name    string
		cfg     *DiscoveryOptions
		wantErr bool
	}{
		{
			name:    "NilOptions",
			cfg:     nil,
			wantErr: false,
		},
		{
			name:    "DefaultOptions",
			cfg:     &defaults,
			wantErr: false,
		},
		{
			name: "DiscoverAtRendezvous",
			cfg: &DiscoveryOptions{
				Discover:       true,
				Rendezvous:     "test",
				ConnectTimeout: time.Second,
			},
			wantErr: false,
		},
		{
			name: "DiscoverNoRendezvous",
			cfg: &DiscoveryOptions{
				Discover:       true,
				Rendezvous:     "",
				ConnectTimeout: time.Second,
			},
			wantErr: true,
		},
		{
			name: "AnnounceNoTTL",
			cfg: &DiscoveryOptions{
				Announce:       true,
				Rendezvous:     "test",
				ConnectTimeout: time.Second,
				AnnounceTTL:    0,
			},
			wantErr: true,
		},
		{
			name: "AnnounceWithTTLNoTimeout",
			cfg: &DiscoveryOptions{
				Announce:       true,
				Rendezvous:     "test",
				ConnectTimeout: 0,
				AnnounceTTL:    time.Second,
			},
			wantErr: true,
		},
		{
			name: "AnnounceValid",
			cfg: &DiscoveryOptions{
				Announce:       true,
				Rendezvous:     "test",
				ConnectTimeout: time.Second,
				AnnounceTTL:    time.Second,
			},
			wantErr: false,
		},
		{
			name: "InvalidLocalAddrs",
			cfg: &DiscoveryOptions{
				Announce:         true,
				Rendezvous:       "test",
				ConnectTimeout:   time.Second,
				AnnounceTTL:      time.Second,
				LocalAddrs:       []string{"invalid"},
				BootstrapServers: []string{"/ip4/127.0.0.1/tcp/8080"},
			},
			wantErr: true,
		},
		{
			name: "InvalidBootstrapServers",
			cfg: &DiscoveryOptions{
				Announce:         true,
				Rendezvous:       "test",
				ConnectTimeout:   time.Second,
				AnnounceTTL:      time.Second,
				LocalAddrs:       []string{"/ip4/127.0.0.1/tcp/8080"},
				BootstrapServers: []string{"invalid"},
			},
			wantErr: true,
		},
		{
			name: "ValidAnnounceAddrs",
			cfg: &DiscoveryOptions{
				Announce:         true,
				Rendezvous:       "test",
				ConnectTimeout:   time.Second,
				AnnounceTTL:      time.Second,
				LocalAddrs:       []string{"/ip4/127.0.0.1/tcp/8080"},
				BootstrapServers: []string{"/ip4/127.0.0.1/tcp/8080"},
			},
			wantErr: false,
		},
		{
			name: "ValidDiscoverAddrs",
			cfg: &DiscoveryOptions{
				Discover:         true,
				Rendezvous:       "test",
				ConnectTimeout:   time.Second,
				LocalAddrs:       []string{"/ip4/127.0.0.1/tcp/8080"},
				BootstrapServers: []string{"/ip4/127.0.0.1/tcp/8080"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			if tt.cfg != nil {
				// Make sure we can bind to flags without panicking.
				fs := pflag.NewFlagSet("test", pflag.PanicOnError)
				tt.cfg.BindFlags("test", fs)
			}
			err := tt.cfg.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestDiscoveryConfigHostOptions(t *testing.T) {}
