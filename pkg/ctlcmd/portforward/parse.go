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

package portforward

import (
	"fmt"
	"strconv"
	"strings"
)

// PortForwardSpec is a port forward spec.
type PortForwardSpec struct {
	// LocalPort is the local port to forward.
	LocalPort uint32
	// RemoteAddress is the remote address to forward to.
	RemoteAddress string
	// RemotePort is the remote port to forward to.
	RemotePort uint32
}

// RemoteString returns the remote address and port as a string.
func (s PortForwardSpec) RemoteString() string {
	return fmt.Sprintf("%s:%d", s.RemoteAddress, s.RemotePort)
}

// ParsePortForwardSpec parses a port forward spec into its constituent parts.
func ParsePortForwardSpec(specStr string) (spec PortForwardSpec, err error) {
	spec.RemoteAddress = "127.0.0.1"
	spl := strings.Split(specStr, ":")
	switch len(spl) {
	case 1:
		remotePortStr := spl[0]
		var port uint64
		port, err = strconv.ParseUint(remotePortStr, 10, 32)
		if err != nil {
			err = fmt.Errorf("invalid port forward spec %q: %w", spec, err)
			return
		}
		spec.RemotePort = uint32(port)
	case 2:
		localPortStr, remotePortStr := spl[0], spl[1]
		var localPort, remotePort uint64
		localPort, err = strconv.ParseUint(localPortStr, 10, 32)
		if err != nil {
			err = fmt.Errorf("invalid port forward spec %q: %w", spec, err)
			return
		}
		spec.LocalPort = uint32(localPort)
		remotePort, err = strconv.ParseUint(remotePortStr, 10, 32)
		if err != nil {
			err = fmt.Errorf("invalid port forward spec %q: %w", spec, err)
			return
		}
		spec.RemotePort = uint32(remotePort)
	case 3:
		var localPortStr, remotePortStr string
		var localPort, remotePort uint64
		localPortStr, remoteAddress, remotePortStr := spl[0], spl[1], spl[2]
		spec.RemoteAddress = remoteAddress
		localPort, err = strconv.ParseUint(localPortStr, 10, 32)
		if err != nil {
			err = fmt.Errorf("invalid port forward spec %q: %w", spec, err)
			return
		}
		spec.LocalPort = uint32(localPort)
		remotePort, err = strconv.ParseUint(remotePortStr, 10, 32)
		if err != nil {
			err = fmt.Errorf("invalid port forward spec %q: %w", spec, err)
			return
		}
		spec.RemotePort = uint32(remotePort)
	default:
		err = fmt.Errorf("invalid port forward spec %q", spec)
	}
	return
}
