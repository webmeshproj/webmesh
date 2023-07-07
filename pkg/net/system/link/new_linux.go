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

	"github.com/webmeshproj/node/pkg/context"
)

// New creates a new WireGuard interface on the host system with the given name.
func New(ctx context.Context, name string, mtu uint32) error {
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
