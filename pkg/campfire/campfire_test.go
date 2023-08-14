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
	"context"
	"fmt"
	"testing"

	"github.com/webmeshproj/webmesh/pkg/services/turn"
)

func TestCampfire(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	campURI := "camp://9d4e8faba9a93ef397554dc4:hLxK4U49l6fcZLH0@a.relay.metered.ca/?fingerprint#abcdefghijklmnopqrstuvwx12345678"
	ourcamp, err := ParseCampfireURI(campURI)
	if err != nil {
		t.Fatal(err)
	}

	cf, err := Wait(ctx, ourcamp)
	if err != nil {
		t.Fatal(err)
	}

	waitErrs := make(chan error)
	go func() {
		defer close(waitErrs)
		conn, err := cf.Accept()
		if err != nil {
			waitErrs <- err
			return
		}
		defer conn.Close()
		_, err = conn.Write([]byte("hello"))
		if err != nil {
			waitErrs <- err
			return
		}
		b := make([]byte, 5)
		n, err := conn.Read(b)
		if err != nil {
			waitErrs <- err
			return
		}
		if string(b[:n]) != "world" {
			waitErrs <- fmt.Errorf("expected 'world' got %s", string(b[:n]))
			return
		}
	}()

	conn, err := Join(ctx, ourcamp)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	b := make([]byte, 5)
	n, err := conn.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(b[:n]) != "hello" {
		t.Fatalf("expected 'hello' got %s", string(b[:n]))
	}
	_, err = conn.Write([]byte("world"))
	if err != nil {
		t.Fatal(err)
	}
	for err := range waitErrs {
		t.Fatal(err)
	}
}

func setupTest(t *testing.T) (turnServer string) {
	t.Helper()
	server, err := turn.NewServer(&turn.Options{
		PublicIP:        "127.0.0.1",
		RelayAddressUDP: "0.0.0.0",
		ListenUDP:       ":0",
		EnableCampfire:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Close()
	})
	return fmt.Sprintf("turn:127.0.0.1:%d", server.ListenPort())
}
