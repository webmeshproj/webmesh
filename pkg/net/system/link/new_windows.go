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
	"errors"
	"fmt"

	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// NewKernel creates a new kernel WireGuard interface on the host system with the given name.
func NewKernel(ctx context.Context, name string, mtu uint32) error {
	return errors.New("kernel interfaces not supported on windows")
}

// NewTUN creates a new WireGuard interface using the userspace tun driver.
func NewTUN(ctx context.Context, name string, mtu uint32) (realName string, closer func(), err error) {
	tun, err := tun.CreateTUN(name, int(mtu))
	if err != nil {
		err = fmt.Errorf("create tun: %w", err)
		return
	}
	realName, err = tun.Name()
	if err != nil {
		err = fmt.Errorf("get tun name: %w", err)
		return
	}
	device := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(
		func() int {
			if context.LoggerFrom(ctx).Handler().Enabled(context.Background(), slog.LevelDebug) {
				return device.LogLevelVerbose
			}
			return device.LogLevelError
		}(),
		fmt.Sprintf("(%s) ", realName),
	))
	uapi, err := ipc.UAPIListen(realName)
	if err != nil {
		device.Close()
		err = fmt.Errorf("uapi listen: %w", err)
		return
	}
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
