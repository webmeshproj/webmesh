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

package plugins

import (
	"flag"
	"fmt"
	"net"
	"os"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"

	"github.com/webmeshproj/node/pkg/context"
)

// Serve is a convenience function for serving a plugin. It should be used
// by plugins that are intended to be run as a separate process.
func Serve(ctx context.Context, plugin v1.PluginServer) error {
	addr := flag.String("listen-address", "127.0.0.1:0", "address to listen on")
	broadcastFd := flag.Int("broadcast-fd", -1, "file descriptor to broadcast the address on")
	flag.Parse()
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	if *broadcastFd != -1 {
		if err := broadcastAddress(*broadcastFd, ln.Addr().String()); err != nil {
			return err
		}
	}
	s := grpc.NewServer()
	go func() {
		<-ctx.Done()
		defer ln.Close()
		s.GracefulStop()
	}()
	v1.RegisterPluginServer(s, plugin)
	if err := s.Serve(ln); err != nil {
		return err
	}
	return nil
}

func broadcastAddress(fd int, addr string) error {
	f := os.NewFile(uintptr(fd), "broadcast")
	if f == nil {
		return fmt.Errorf("invalid file descriptor %d", fd)
	}
	defer f.Close()
	if _, err := f.WriteString(addr); err != nil {
		return err
	}
	return nil
}
