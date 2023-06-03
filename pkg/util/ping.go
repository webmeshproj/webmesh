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

package util

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/go-ping/ping"
)

// Ping sends ICMP echo requests to the given address. The context must
// have a timeout set and is used for the duration of the ping. The
// function returns an error if no replies were received.
func Ping(ctx context.Context, addr netip.Addr) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return fmt.Errorf("no deadline set")
	}
	pinger, err := ping.NewPinger(addr.String())
	if err != nil {
		return fmt.Errorf("create pinger: %w", err)
	}
	pinger.Timeout = time.Until(deadline)
	pinger.Interval = 500 * time.Millisecond
	if os.Geteuid() == 0 {
		pinger.SetPrivileged(true)
	}
	pinger.SetLogger(ping.NoopLogger{})
	err = pinger.Run()
	if err != nil {
		return fmt.Errorf("run pinger: %w", err)
	}
	stats := pinger.Statistics()
	if stats.PacketsRecv == 0 {
		return fmt.Errorf("no replies received")
	}
	return nil
}
