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

package link

import (
	"fmt"

	"github.com/jsimonetti/rtnetlink"
	"golang.org/x/exp/slog"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// NewKernel creates a new kernel WireGuard interface on the host system with the given name.
func NewKernel(ctx context.Context, name string, mtu uint32) error {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	req := &rtnetlink.LinkMessage{
		Family: unix.AF_UNSPEC,
		Type:   unix.RTM_NEWLINK,
		Flags: unix.NLM_F_REQUEST |
			unix.NLM_F_ACK |
			unix.NLM_F_EXCL | // fail if already exists
			unix.NLM_F_CREATE, // create if it does not exist
		Attributes: &rtnetlink.LinkAttributes{
			Name:  name,
			Alias: &name,
			Type:  unix.ARPHRD_NETROM,
			MTU:   mtu,
			Info:  &rtnetlink.LinkInfo{Kind: "wireguard"},
		},
	}
	context.LoggerFrom(ctx).Debug("creating wireguard interface",
		slog.Any("request", req),
		slog.String("name", name))
	err = conn.Link.New(req)
	if err != nil {
		return fmt.Errorf("create wireguard interface: %w", err)
	}
	return nil
}

// NewTUN creates a new WireGuard interface using the userspace tun driver.
func NewTUN(ctx context.Context, name string, mtu uint32) (realName string, closer func(), err error) {
	// Create the TUN device
	tun, err := tun.CreateTUN(name, int(mtu))
	if err != nil {
		err = fmt.Errorf("create tun: %w", err)
		return
	}
	// Get the real name of the interface
	realName, err = tun.Name()
	if err != nil {
		err = fmt.Errorf("get tun name: %w", err)
		return
	}
	// Open the UAPI socket
	fileuapi, err := ipc.UAPIOpen(realName)
	if err != nil {
		err = fmt.Errorf("uapi open: %w", err)
		tun.Close()
		return
	}
	// Create the tunnel device
	device := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(
		func() int {
			if context.LoggerFrom(ctx).Handler().Enabled(context.Background(), slog.LevelDebug) {
				return device.LogLevelVerbose
			}
			return device.LogLevelError
		}(),
		fmt.Sprintf("(%s) ", realName),
	))
	// Listen for UAPI connections
	uapi, err := ipc.UAPIListen(realName, fileuapi)
	if err != nil {
		device.Close()
		err = fmt.Errorf("uapi listen: %w", err)
		return
	}
	// Handle UAPI connections
	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				return
			}
			go device.IpcHandle(conn)
		}
	}()
	closer = func() {
		uapi.Close()
		device.Close()
	}
	return
}
