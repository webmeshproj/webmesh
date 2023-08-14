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
	"net/url"
	"strings"
)

const (
	defaultStunHost = "stun.l.google.com"
	defaultStunPort = "19302"
	defaultTurnHost = "a.relay.metered.ca"
	defaultTurnPort = "443"
	defaultTurnUser = "9d4e8faba9a93ef397554dc4"
	defaultTurnCred = "hLxK4U49l6fcZLH0"
)

// CampfireURI represents the components parsed from a camp URL.
type CampfireURI struct {
	TURNServers  []string // Username for TURN authentication
	TURNUsername string   // Username for TURN authentication
	TURNPassword string   // Password for TURN authentication
	StunHosts    []string // List of STUN server hosts
	StunPorts    []string // List of STUN server ports
	RemoteHosts  []string // List of remote hosts
	RemotePorts  []string // List of remote ports
	Fingerprint  string   // Raw query string, representing fingerprint
	PSK          []byte   // Pre-shared key
}

// ParseURL parses the given rawURL and returns a CampURL struct.
func ParseCampfireURI(rawURL string) (*CampfireURI, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	var out CampfireURI
	out.PSK = []byte(parsedURL.Fragment)
	out.Fingerprint = parsedURL.RawQuery

	// Split the path segments using "/"
	pathSegments := strings.Split(parsedURL.Path, "/")

	// The user:pass@host is intact in the input:
	out.TURNServers = append(out.TURNServers, parsedURL.Host)
	if parsedURL.User != nil {
		out.TURNUsername = parsedURL.User.Username()
		if pwd, ok := parsedURL.User.Password(); ok {
			out.TURNPassword = pwd
		}
	}

	for _, segment := range pathSegments {
		if segment == "" {
			continue // Skip empty segments
		}
		// Split the segment into stun and remote parts using "-"
		parts := strings.Split(segment, "-")
		if len(parts) != 2 {
			// If there is no destination - then its a TURN server.
			out.TURNServers = append(out.TURNServers, segment)
		} else {
			// check for STUN parts:
			stunPart := parts[0]
			remotePart := parts[1]

			// Split stunPart into host and port
			stunHostPort := strings.Split(stunPart, ":")
			if len(stunHostPort) != 2 {
				stunHostPort = []string{defaultStunHost, defaultStunPort} // Use default STUN info
			}
			out.StunHosts = append(out.StunHosts, stunHostPort[0])
			out.StunHosts = append(out.StunHosts, stunHostPort[1])

			// Split remotePart into host and port
			remoteHostPort := strings.Split(remotePart, ":")
			if len(remoteHostPort) != 2 {
				continue // Skip invalid remote parts
			}
			out.RemoteHosts = append(out.RemoteHosts, remoteHostPort[0])
			out.RemotePorts = append(out.RemotePorts, remoteHostPort[1])
		}
	}

	return &out, nil
}
