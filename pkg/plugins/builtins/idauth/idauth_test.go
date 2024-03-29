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

package idauth

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/spf13/pflag"
	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/storage/testutil"
)

func TestIDAuthenticate(t *testing.T) {
	ctx := context.Background()
	var curTime time.Time
	Now = func() time.Time {
		return curTime
	}
	t.Cleanup(func() { Now = time.Now })

	t.Run("WithoutSkew", func(t *testing.T) {
		peer1 := crypto.MustGenerateKey()
		peer2 := crypto.MustGenerateKey()
		peer3 := crypto.MustGenerateKey()

		var c Config
		c.Default()
		c.TimeSkew = -1
		c.AllowedIDs = []string{peer1.ID(), peer2.ID()}
		var p Plugin
		st, err := structpb.NewStruct(c.AsMapStructure())
		if err != nil {
			t.Fatalf("failed to create structpb: %v", err)
		}
		_, err = p.Configure(ctx, &v1.PluginConfiguration{Config: st})
		if err != nil {
			t.Fatalf("failed to configure plugin: %v", err)
		}

		tc := []struct {
			name    string
			id      string
			headers map[string]string
			wantErr bool
		}{
			{
				name: "Peer1ValidSignature",
				id:   peer1.ID(),
				headers: map[string]string{
					peerIDHeader:    peer1.ID(),
					signatureHeader: MustNewAuthSignature(peer1),
				},
				wantErr: false,
			},
			{
				name: "Peer2ValidSignature",
				id:   peer2.ID(),
				headers: map[string]string{
					peerIDHeader:    peer2.ID(),
					signatureHeader: MustNewAuthSignature(peer2),
				},
				wantErr: false,
			},
			{
				name: "Peer3ValidSignature",
				id:   peer3.ID(),
				headers: map[string]string{
					peerIDHeader:    peer3.ID(),
					signatureHeader: MustNewAuthSignature(peer3),
				},
				// We didn't allow peer3
				wantErr: true,
			},
			{
				name: "Peer1SkewedSignature",
				id:   peer1.ID(),
				headers: map[string]string{
					peerIDHeader:    peer1.ID(),
					signatureHeader: mustNewAuthSignatureWithTime(peer1, time.Unix(30, 0)),
				},
				wantErr: true,
			},
			{
				name: "Peer2SkewedSignature",
				id:   peer2.ID(),
				headers: map[string]string{
					peerIDHeader:    peer2.ID(),
					signatureHeader: mustNewAuthSignatureWithTime(peer2, time.Unix(30, 0)),
				},
				wantErr: true,
			},
			{
				name: "Peer3SkewedSignature",
				id:   peer3.ID(),
				headers: map[string]string{
					peerIDHeader:    peer3.ID(),
					signatureHeader: mustNewAuthSignatureWithTime(peer3, time.Unix(30, 0)),
				},
				wantErr: true,
			},
		}
		for _, tt := range tc {
			t.Run(tt.name, func(t *testing.T) {
				resp, err := p.Authenticate(ctx, &v1.AuthenticationRequest{
					Headers: tt.headers,
				})
				if tt.wantErr {
					if err == nil {
						t.Errorf("expected error, got nil")
					}
					return
				}
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if resp == nil {
					t.Fatal("expected response, got nil")
				}
				if resp.GetId() != tt.id {
					t.Errorf("expected id to be %s, got %s", tt.id, resp.GetId())
				}
			})
		}
	})

	t.Run("WithSkew", func(t *testing.T) {
		curTime = time.Unix(60, 0)
		peer1 := crypto.MustGenerateKey()
		peer2 := crypto.MustGenerateKey()
		peer3 := crypto.MustGenerateKey()

		var c Config
		c.Default()
		c.TimeSkew = 1
		c.AllowedIDs = []string{peer1.ID(), peer2.ID()}
		var p Plugin
		st, err := structpb.NewStruct(c.AsMapStructure())
		if err != nil {
			t.Fatalf("failed to create structpb: %v", err)
		}
		_, err = p.Configure(ctx, &v1.PluginConfiguration{Config: st})
		if err != nil {
			t.Fatalf("failed to configure plugin: %v", err)
		}

		tc := []struct {
			name    string
			id      string
			headers map[string]string
			wantErr bool
		}{
			{
				name: "Peer1ValidSignature",
				id:   peer1.ID(),
				headers: map[string]string{
					peerIDHeader:    peer1.ID(),
					signatureHeader: MustNewAuthSignature(peer1),
				},
				wantErr: false,
			},
			{
				name: "Peer2ValidSignature",
				id:   peer2.ID(),
				headers: map[string]string{
					peerIDHeader:    peer2.ID(),
					signatureHeader: MustNewAuthSignature(peer2),
				},
				wantErr: false,
			},
			{
				name: "Peer3ValidSignature",
				id:   peer3.ID(),
				headers: map[string]string{
					peerIDHeader:    peer3.ID(),
					signatureHeader: MustNewAuthSignature(peer3),
				},
				// We didn't allow peer3
				wantErr: true,
			},
			{
				name: "Peer1NegativeSkewedSignature",
				id:   peer1.ID(),
				headers: map[string]string{
					peerIDHeader:    peer1.ID(),
					signatureHeader: mustNewAuthSignatureWithTime(peer1, time.Unix(30, 0)),
				},
				wantErr: false,
			},
			{
				name: "Peer2NegativeSkewedSignature",
				id:   peer2.ID(),
				headers: map[string]string{
					peerIDHeader:    peer2.ID(),
					signatureHeader: mustNewAuthSignatureWithTime(peer2, time.Unix(30, 0)),
				},
				wantErr: false,
			},
			{
				name: "Peer3NegativeSkewedSignature",
				id:   peer3.ID(),
				headers: map[string]string{
					peerIDHeader:    peer3.ID(),
					signatureHeader: mustNewAuthSignatureWithTime(peer3, time.Unix(30, 0)),
				},
				wantErr: true,
			},
			{
				name: "Peer1PositiveSkewedSignature",
				id:   peer1.ID(),
				headers: map[string]string{
					peerIDHeader:    peer1.ID(),
					signatureHeader: mustNewAuthSignatureWithTime(peer1, time.Unix(90, 0)),
				},
				wantErr: false,
			},
			{
				name: "Peer2PositiveSkewedSignature",
				id:   peer2.ID(),
				headers: map[string]string{
					peerIDHeader:    peer2.ID(),
					signatureHeader: mustNewAuthSignatureWithTime(peer2, time.Unix(90, 0)),
				},
				wantErr: false,
			},
			{
				name: "Peer3PositiveSkewedSignature",
				id:   peer3.ID(),
				headers: map[string]string{
					peerIDHeader:    peer3.ID(),
					signatureHeader: mustNewAuthSignatureWithTime(peer3, time.Unix(90, 0)),
				},
				wantErr: true,
			},
			{
				name: "Peer1OverSkewedSignature",
				id:   peer1.ID(),
				headers: map[string]string{
					peerIDHeader:    peer1.ID(),
					signatureHeader: mustNewAuthSignatureWithTime(peer1, time.Unix(120, 0)),
				},
				wantErr: true,
			},
			{
				name: "Peer2OverSkewedSignature",
				id:   peer2.ID(),
				headers: map[string]string{
					peerIDHeader:    peer2.ID(),
					signatureHeader: mustNewAuthSignatureWithTime(peer2, time.Unix(120, 0)),
				},
				wantErr: true,
			},
			{
				name: "Peer1UnderSkewedSignature",
				id:   peer1.ID(),
				headers: map[string]string{
					peerIDHeader:    peer1.ID(),
					signatureHeader: mustNewAuthSignatureWithTime(peer1, time.Unix(0, 0)),
				},
				wantErr: true,
			},
			{
				name: "Peer2UnderSkewedSignature",
				id:   peer2.ID(),
				headers: map[string]string{
					peerIDHeader:    peer2.ID(),
					signatureHeader: mustNewAuthSignatureWithTime(peer2, time.Unix(0, 0)),
				},
				wantErr: true,
			},
		}
		for _, tt := range tc {
			t.Run(tt.name, func(t *testing.T) {
				resp, err := p.Authenticate(ctx, &v1.AuthenticationRequest{
					Headers: tt.headers,
				})
				if tt.wantErr {
					if err == nil {
						t.Errorf("expected error, got nil")
					}
					return
				}
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if resp == nil {
					t.Fatal("expected response, got nil")
				}
				if resp.GetId() != tt.id {
					t.Errorf("expected id to be %s, got %s", tt.id, resp.GetId())
				}
			})
		}
	})
}

func TestConfigureIDAuthPlugin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("PluginInfo", func(t *testing.T) {
		var p Plugin
		info, err := p.GetInfo(ctx, nil)
		if err != nil {
			t.Fatalf("failed to get plugin info: %v", err)
		}
		if info.Name != "id-auth" {
			t.Errorf("expected name to be id-auth, got %s", info.Name)
		}
		var hasAuthCap bool
		for _, cap := range info.Capabilities {
			if cap == v1.PluginInfo_AUTH {
				hasAuthCap = true
				break
			}
		}
		if !hasAuthCap {
			t.Errorf("expected capabilities to contain AUTH")
		}
	})

	t.Run("Defaults", func(t *testing.T) {
		var c Config
		c.Default()
		conf, err := structpb.NewStruct(c.AsMapStructure())
		if err != nil {
			t.Fatalf("failed to create structpb: %v", err)
		}
		req := &v1.PluginConfiguration{Config: conf}
		var p Plugin
		_, err = p.Configure(ctx, req)
		if err == nil {
			t.Errorf("Expected error for no allowed IDs")
		}
		c.AllowedIDs = []string{"foo"}
		conf, err = structpb.NewStruct(c.AsMapStructure())
		if err != nil {
			t.Fatalf("failed to create structpb: %v", err)
		}
		req = &v1.PluginConfiguration{Config: conf}
		_, err = p.Configure(ctx, req)
		if err != nil {
			t.Errorf("Expected no error for allowed IDs")
		}
		if ok := p.allowedIDs.HasID("foo"); !ok {
			t.Errorf("Expected foo to be allowed")
		}
	})

	t.Run("UnwatchedIDSources", func(t *testing.T) {
		t.Run("FileSource", func(t *testing.T) {
			var c Config
			c.Default()
			idSrc, err := os.CreateTemp("", "idauth-test")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(idSrc.Name())
			_, err = idSrc.WriteString("foo\nbar\nbaz\n")
			if err != nil {
				t.Fatalf("failed to write to temp file: %v", err)
			}
			c.IDFiles = []string{idSrc.Name()}
			conf, err := structpb.NewStruct(c.AsMapStructure())
			if err != nil {
				t.Fatalf("failed to create structpb: %v", err)
			}
			req := &v1.PluginConfiguration{Config: conf}
			var p Plugin
			_, err = p.Configure(ctx, req)
			if err != nil {
				t.Errorf("Expected no error for allowed IDs")
			}
			if ok := p.allowedIDs.HasID("foo"); !ok {
				t.Errorf("Expected foo to be allowed")
			}
			if ok := p.allowedIDs.HasID("bar"); !ok {
				t.Errorf("Expected bar to be allowed")
			}
			// It should work the same with a file:// prefix
			c.IDFiles = []string{"file://" + idSrc.Name()}
			conf, err = structpb.NewStruct(c.AsMapStructure())
			if err != nil {
				t.Fatalf("failed to create structpb: %v", err)
			}
			req = &v1.PluginConfiguration{Config: conf}
			_, err = p.Configure(ctx, req)
			if err != nil {
				t.Errorf("Expected no error for allowed IDs")
			}
			if ok := p.allowedIDs.HasID("foo"); !ok {
				t.Errorf("Expected foo to be allowed")
			}
			if ok := p.allowedIDs.HasID("bar"); !ok {
				t.Errorf("Expected bar to be allowed")
			}
			// Write another ID to the file and it should remain unchanged
			_, err = idSrc.WriteString("qux\n")
			if err != nil {
				t.Fatalf("failed to write to temp file: %v", err)
			}
			if ok := p.allowedIDs.HasID("qux"); ok {
				t.Errorf("Expected qux to not be allowed")
			}
		})
		t.Run("HTTPSource", func(t *testing.T) {
			var c Config
			c.Default()
			mux := http.NewServeMux()
			idResp := []byte("foo\nbar\nbaz\n")
			mux.HandleFunc("/ids", func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(idResp)
			})
			srv := &http.Server{Handler: mux}
			ln, err := net.ListenTCP("tcp", &net.TCPAddr{Port: 0})
			if err != nil {
				t.Fatalf("failed to listen: %v", err)
			}
			go func() {
				if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
					t.Errorf("failed to start server: %v", err)
				}
			}()
			t.Cleanup(func() { _ = srv.Shutdown(ctx) })
			t.Log("Server started on", ln.Addr().String())
			c.IDFiles = []string{"http://" + ln.Addr().String() + "/ids"}
			conf, err := structpb.NewStruct(c.AsMapStructure())
			if err != nil {
				t.Fatalf("failed to create structpb: %v", err)
			}
			req := &v1.PluginConfiguration{Config: conf}
			var p Plugin
			_, err = p.Configure(ctx, req)
			if err != nil {
				t.Errorf("Expected no error for allowed IDs")
			}
			if ok := p.allowedIDs.HasID("foo"); !ok {
				t.Errorf("Expected foo to be allowed")
			}
			if ok := p.allowedIDs.HasID("bar"); !ok {
				t.Errorf("Expected bar to be allowed")
			}
			// Change the ID response and the IDs should not change
			idResp = []byte("qux\n")
			if ok := p.allowedIDs.HasID("foo"); !ok {
				t.Errorf("Expected foo to be allowed")
			}
			if ok := p.allowedIDs.HasID("bar"); !ok {
				t.Errorf("Expected bar to be allowed")
			}
			if ok := p.allowedIDs.HasID("qux"); ok {
				t.Errorf("Expected qux to not be allowed")
			}
		})
	})

	t.Run("WatchedIDSources", func(t *testing.T) {
		t.Run("FileSource", func(t *testing.T) {
			var p Plugin
			t.Cleanup(func() { _, _ = p.Close(ctx, nil) })
			var c Config
			c.Default()
			c.WatchIDFiles = true
			idDir, err := os.MkdirTemp("", "idauth-test")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			t.Cleanup(func() { os.RemoveAll(idDir) })
			idfile := filepath.Join(idDir, "allowed-ids.txt")
			idSrc, err := os.Create(idfile)
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			_, err = idSrc.WriteString("foo\nbar\nbaz\n")
			if err != nil {
				t.Fatalf("failed to write to temp file: %v", err)
			}
			err = idSrc.Close()
			if err != nil {
				t.Fatalf("failed to close temp file: %v", err)
			}
			c.IDFiles = []string{idfile}
			conf, err := structpb.NewStruct(c.AsMapStructure())
			if err != nil {
				t.Fatalf("failed to create structpb: %v", err)
			}
			req := &v1.PluginConfiguration{Config: conf}
			_, err = p.Configure(ctx, req)
			if err != nil {
				t.Errorf("Expected no error for allowed IDs")
			}
			p.mu.Lock()
			if ok := p.allowedIDs.HasID("foo"); !ok {
				t.Errorf("Expected foo to be allowed")
			}
			if ok := p.allowedIDs.HasID("bar"); !ok {
				t.Errorf("Expected bar to be allowed")
			}
			p.mu.Unlock()
			// Delete the file and the IDs should no longer be allowed
			time.Sleep(time.Second)
			err = os.Remove(idfile)
			if err != nil {
				t.Fatalf("failed to write to temp file: %v", err)
			}
			ok := testutil.Eventually[bool](func() bool {
				p.mu.Lock()
				defer p.mu.Unlock()
				return p.allowedIDs.HasID("foo")
			}).ShouldEqual(time.Second*15, time.Second, false)
			if !ok {
				t.Fatal("Expected foo to not be allowed")
			}
			ok = testutil.Eventually[bool](func() bool {
				p.mu.Lock()
				defer p.mu.Unlock()
				return p.allowedIDs.HasID("bar")
			}).ShouldEqual(time.Second*15, time.Second, false)
			if !ok {
				t.Fatal("Expected bar to not be allowed")
			}
			// Recreate the file and we should have new ids we trust
			idSrc, err = os.Create(idfile)
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			_, err = idSrc.WriteString("qux\n")
			if err != nil {
				t.Fatalf("failed to write to temp file: %v", err)
			}
			err = idSrc.Close()
			if err != nil {
				t.Fatalf("failed to close temp file: %v", err)
			}
			ok = testutil.Eventually[bool](func() bool {
				p.mu.Lock()
				defer p.mu.Unlock()
				return p.allowedIDs.HasID("qux")
			}).ShouldEqual(time.Second*15, time.Second, true)
			if !ok {
				t.Fatal("Expected qux to be allowed")
			}
		})

		t.Run("HTTPSource", func(t *testing.T) {
			var p Plugin
			t.Cleanup(func() { _, _ = p.Close(ctx, nil) })
			var c Config
			c.Default()
			mux := http.NewServeMux()
			idResp := []byte("foo\nbar\nbaz\n")
			mux.HandleFunc("/ids", func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(idResp)
			})
			srv := &http.Server{Handler: mux}
			ln, err := net.ListenTCP("tcp", &net.TCPAddr{Port: 0})
			if err != nil {
				t.Fatalf("failed to listen: %v", err)
			}
			go func() {
				if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
					t.Errorf("failed to start server: %v", err)
				}
			}()
			t.Cleanup(func() { _ = srv.Shutdown(ctx) })
			t.Log("Server started on", ln.Addr().String())
			c.IDFiles = []string{"http://" + ln.Addr().String() + "/ids"}
			c.WatchIDFiles = true
			c.WatchInterval = time.Second
			conf, err := structpb.NewStruct(c.AsMapStructure())
			if err != nil {
				t.Fatalf("failed to create structpb: %v", err)
			}
			req := &v1.PluginConfiguration{Config: conf}
			_, err = p.Configure(ctx, req)
			if err != nil {
				t.Errorf("Expected no error for allowed IDs")
			}
			p.mu.Lock()
			if ok := p.allowedIDs.HasID("foo"); !ok {
				t.Errorf("Expected foo to be allowed")
			}
			if ok := p.allowedIDs.HasID("bar"); !ok {
				t.Errorf("Expected bar to be allowed")
			}
			if ok := p.allowedIDs.HasID("baz"); !ok {
				t.Errorf("Expected baz to be allowed")
			}
			p.mu.Unlock()
			// Change the ID response and the IDs should change
			idResp = []byte("qux\n")
			ok := testutil.Eventually[bool](func() bool {
				p.mu.Lock()
				defer p.mu.Unlock()
				return p.allowedIDs.HasID("qux")
			}).ShouldEqual(time.Second*15, time.Second, true)
			if !ok {
				t.Fatal("Expected qux to be allowed")
			}
			ok = testutil.Eventually[bool](func() bool {
				p.mu.Lock()
				defer p.mu.Unlock()
				return p.allowedIDs.HasID("foo")
			}).ShouldEqual(time.Second*15, time.Second, false)
			if !ok {
				t.Fatal("Expected foo to not be allowed")
			}
			ok = testutil.Eventually[bool](func() bool {
				p.mu.Lock()
				defer p.mu.Unlock()
				return p.allowedIDs.HasID("bar")
			}).ShouldEqual(time.Second*15, time.Second, false)
			if !ok {
				t.Fatal("Expected bar to not be allowed")
			}
			ok = testutil.Eventually[bool](func() bool {
				p.mu.Lock()
				defer p.mu.Unlock()
				return p.allowedIDs.HasID("baz")
			}).ShouldEqual(time.Second*15, time.Second, false)
			if !ok {
				t.Fatal("Expected baz to not be allowed")
			}
		})
	})
}

func TestIDAuthConfiguration(t *testing.T) {
	t.Parallel()

	t.Run("FlagBinder", func(t *testing.T) {
		var c Config
		// Make sure it binds to a flagset without panicking
		c.Default()
		c.BindFlags("test", pflag.NewFlagSet("test", pflag.ContinueOnError))
		c.IDFiles = []string{"foo"}
		c.AllowedIDs = []string{"bar"}

		t.Run("GetMapStructure", func(t *testing.T) {
			ms := c.AsMapStructure()
			if ms == nil {
				t.Error("expected non-nil mapstructure")
			}
			allowedIDSlc := make([]string, len(c.AllowedIDs))
			for i, id := range ms["allowed-ids"].([]any) {
				allowedIDSlc[i] = id.(string)
			}
			if !slices.Equal(c.AllowedIDs, allowedIDSlc) {
				t.Errorf("expected allowed-ids to be %v, got %v", c.AllowedIDs, allowedIDSlc)
			}
			idFileSlc := make([]string, len(c.IDFiles))
			for i, id := range ms["id-files"].([]any) {
				idFileSlc[i] = id.(string)
			}
			if !slices.Equal(c.IDFiles, idFileSlc) {
				t.Errorf("expected id-files to be %v, got %v", c.IDFiles, idFileSlc)
			}
			if ms["time-skew"].(int) != c.TimeSkew {
				t.Errorf("expected time-skew to be %d, got %d", c.TimeSkew, ms["time-skew"].(int))
			}
			if ms["watch-id-files"].(bool) != c.WatchIDFiles {
				t.Errorf("expected watch-id-files to be %t, got %t", c.WatchIDFiles, ms["watch-id-files"].(bool))
			}
			if time.Duration(ms["watch-interval"].(int)) != c.WatchInterval {
				t.Errorf("expected watch-interval to be %s, got %s", c.WatchInterval.String(), time.Duration(ms["watch-interval"].(int)).String())
			}
			if ms["remote-fetch-retries"].(int) != c.RemoteFetchRetries {
				t.Errorf("expected remote-fetch-retries to be %d, got %d", c.RemoteFetchRetries, ms["remote-fetch-retries"].(int))
			}
			if time.Duration(ms["remote-fetch-retry-interval"].(int)) != c.RemoteFetchRetryInterval {
				t.Errorf("expected remote-fetch-retry-interval to be %s, got %s", c.RemoteFetchRetryInterval.String(), time.Duration(ms["remote-fetch-retry-interval"].(int)).String())
			}
		})

		t.Run("SetMapStructure", func(t *testing.T) {
			ms := c.AsMapStructure()
			ms["allowed-ids"] = []any{"foo", "bar"}
			ms["id-files"] = []any{"baz", "qux"}
			ms["time-skew"] = 10
			ms["watch-id-files"] = true
			ms["watch-interval"] = 20
			ms["remote-fetch-retries"] = 30
			ms["remote-fetch-retry-interval"] = 40
			c.SetMapStructure(ms)
			if !slices.Equal(c.AllowedIDs, []string{"foo", "bar"}) {
				t.Errorf("expected allowed-ids to be %v, got %v", []string{"foo", "bar"}, c.AllowedIDs)
			}
			if !slices.Equal(c.IDFiles, []string{"baz", "qux"}) {
				t.Errorf("expected id-files to be %v, got %v", []string{"baz", "qux"}, c.IDFiles)
			}
			if c.TimeSkew != 10 {
				t.Errorf("expected time-skew to be %d, got %d", 10, c.TimeSkew)
			}
			if c.WatchIDFiles != true {
				t.Errorf("expected watch-id-files to be %t, got %t", true, c.WatchIDFiles)
			}
			if c.WatchInterval != 20 {
				t.Errorf("expected watch-interval to be %d, got %d", 20, c.WatchInterval)
			}
			if c.RemoteFetchRetries != 30 {
				t.Errorf("expected remote-fetch-retries to be %d, got %d", 30, c.RemoteFetchRetries)
			}
			if c.RemoteFetchRetryInterval != 40 {
				t.Errorf("expected remote-fetch-retry-interval to be %d, got %d", 40, c.RemoteFetchRetryInterval)
			}
		})
	})
	t.Run("Defaults", func(t *testing.T) {
		var c Config
		c.Default()
		if c.TimeSkew != DefaultTimeSkew {
			t.Errorf("expected default TimeSkew to be %d, got %d", DefaultTimeSkew, c.TimeSkew)
		}
		if c.RemoteFetchRetryInterval != DefaultRemoteFetchRetryInterval {
			t.Errorf("expected default RemoteFetchRetryInterval to be %s, got %s", DefaultRemoteFetchRetryInterval.String(), c.RemoteFetchRetryInterval)
		}
		if c.RemoteFetchRetries != DefaultRemoteFetchRetries {
			t.Errorf("expected default RemoteFetchRetries to be %d, got %d", DefaultRemoteFetchRetries, c.RemoteFetchRetries)
		}
		if c.WatchInterval != DefaultWatchInterval {
			t.Errorf("expected default WatchInterval to be %s, got %s", DefaultWatchInterval.String(), c.WatchInterval)
		}
	})
}

func TestIDAuthAllowedIDs(t *testing.T) {
	t.Parallel()

	tc := []struct {
		name    string
		allowed AllowedIDs
		ids     map[string]bool
	}{
		{
			name:    "Empty",
			allowed: AllowedIDs{},
			ids: map[string]bool{
				"foo": false,
				"bar": false,
				"baz": false,
			},
		},
		{
			name: "EmptySources",
			allowed: AllowedIDs{
				"src1": {},
				"src2": {},
			},
			ids: map[string]bool{
				"foo": false,
				"bar": false,
				"baz": false,
			},
		},
		{
			name: "NonEmptySources",
			allowed: AllowedIDs{
				"src1": {"node-a": struct{}{}},
				"src2": {"node-b": struct{}{}},
			},
			ids: map[string]bool{
				"foo":    false,
				"bar":    false,
				"baz":    false,
				"node-a": true,
				"node-b": true,
			},
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			for id, want := range tt.ids {
				if got := tt.allowed.HasID(id); got != want {
					t.Errorf("AllowedIDs.Allowed() = %v, want %v", got, want)
				}
			}
		})
	}
}

func TestIDAuthCurrentSigData(t *testing.T) {
	Now = func() time.Time {
		return time.Unix(0, 0)
	}
	t.Cleanup(func() { Now = time.Now })
	c := Config{TimeSkew: 0}
	sigData := c.CurrentSigData("test")
	if len(sigData) != 1 {
		t.Fatalf("expected sigData to be 1 elements, got %d", len(sigData))
	}
	if !bytes.Equal(sigData[0], []byte("test:0")) {
		t.Errorf("expected sigData to be test:0, got %s", sigData[0])
	}

	c = Config{TimeSkew: 1}
	sigData = c.CurrentSigData("test")
	if len(sigData) != 3 {
		t.Fatalf("expected sigData to be 3 elements, got %d", len(sigData))
	}
	if !bytes.Equal(sigData[0], []byte("test:0")) {
		t.Errorf("expected sigData to be test:0, got %s", sigData[0])
	}
	if !bytes.Equal(sigData[1], []byte("test:-30")) {
		t.Errorf("expected sigData to be test:-30, got %s", sigData[1])
	}
	if !bytes.Equal(sigData[2], []byte("test:30")) {
		t.Errorf("expected sigData to be test:30, got %s", sigData[2])
	}

	c = Config{TimeSkew: 2}
	sigData = c.CurrentSigData("test")
	if len(sigData) != 5 {
		t.Fatalf("expected sigData to be 5 elements, got %d", len(sigData))
	}
	if !bytes.Equal(sigData[0], []byte("test:0")) {
		t.Errorf("expected sigData to be test:0, got %s", sigData[0])
	}
	if !bytes.Equal(sigData[1], []byte("test:-30")) {
		t.Errorf("expected sigData to be test:-30, got %s", sigData[1])
	}
	if !bytes.Equal(sigData[2], []byte("test:30")) {
		t.Errorf("expected sigData to be test:30, got %s", sigData[2])
	}
	if !bytes.Equal(sigData[3], []byte("test:-60")) {
		t.Errorf("expected sigData to be test:-60, got %s", sigData[3])
	}
	if !bytes.Equal(sigData[4], []byte("test:60")) {
		t.Errorf("expected sigData to be test:60, got %s", sigData[4])
	}
}
