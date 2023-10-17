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

package dns

import (
	"bufio"
	"context"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/webmeshproj/webmesh/pkg/meshnet/system/routes"
)

func addServers(iface string, servers []netip.AddrPort) error {
	primaryIface, err := getPrimaryIface()
	if err != nil {
		return err
	}
	args := []string{"-setdnsservers", primaryIface}
	for _, server := range servers {
		args = append(args, server.String())
	}
	return exec.Command("networksetup", args...).Run()
}

func removeServers(iface string, servers []netip.AddrPort) error {
	primaryIface, err := getPrimaryIface()
	if err != nil {
		return err
	}
	// Get the current servers for the interface
	out, err := exec.Command("networksetup", "-getdnsservers", primaryIface).Output()
	if err != nil {
		return err
	}
	var current []netip.AddrPort
	for _, server := range strings.Split(string(out), "\n") {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		addr, err := netip.ParseAddrPort(server)
		if err != nil {
			// This likely means there are no servers in the list
			continue
		}
		current = append(current, addr)
	}
	// Trim current of any servers that are in the list to remove
	for _, server := range servers {
		for i, currentServer := range current {
			if currentServer.Addr() == server.Addr() && currentServer.Port() == server.Port() {
				current = append(current[:i], current[i+1:]...)
			}
		}
	}
	// Clear the servers
	err = exec.Command("networksetup", "-setdnsservers", primaryIface, "empty").Run()
	if err != nil {
		return err
	}
	// Add the remaining servers back
	return addServers(iface, current)
}

func addSearchDomains(iface string, domains []string) error {
	return nil
}

func removeSearchDomains(iface string, domains []string) error {
	return nil
}

func loadSystemConfig() (*DNSConfig, error) {
	conf := &DNSConfig{
		Ndots:    1,
		Timeout:  5 * time.Second,
		Attempts: 2,
	}
	f, err := openResolvConf()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 0 && (line[0] == ';' || line[0] == '#') {
			// comment.
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			if len(fields) > 1 {
				var addrport netip.AddrPort
				// Try to parse as a regular address
				addr, err := netip.ParseAddr(fields[1])
				if err == nil {
					// Default to port 53
					addrport = netip.AddrPortFrom(addr, 53)
				} else {
					// Try to parse as an address with port
					addrport, err = netip.ParseAddrPort(fields[1])
					if err != nil {
						continue
					}
				}
				conf.Servers = append(conf.Servers, addrport.String())
			}
		case "domain":
			if len(fields) > 1 {
				conf.Search = append(conf.Search, fields[1])
			}
		case "search":
			if len(fields) > 1 {
				conf.Search = append(conf.Search, fields[1:]...)
			}
		case "options":
			for _, opt := range fields[1:] {
				switch {
				case strings.HasPrefix(opt, "ndots:"):
					dots, err := strconv.Atoi(opt[6:])
					if err == nil {
						conf.Ndots = dots
					}
				case strings.HasPrefix(opt, "timeout:"):
					timeout, err := strconv.Atoi(opt[8:])
					if err == nil {
						conf.Timeout = time.Duration(timeout) * time.Second
					}
				case strings.HasPrefix(opt, "attempts:"):
					attempts, err := strconv.Atoi(opt[9:])
					if err == nil {
						conf.Attempts = attempts
					}
				case opt == "use-vc" || opt == "usevc" || opt == "tcp":
					conf.UseTCP = true
				}
			}
		}
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return nil, err
	}
	if len(conf.Servers) == 0 {
		conf.Servers = defaultNS
	}
	return conf, nil
}

func getPrimaryIface() (string, error) {
	gateway, err := routes.GetDefaultGateway(context.Background())
	if err != nil {
		return "", err
	}
	// Figure out which interface uses the default gateway as its router.
	ifaceOut, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return "", err
	}
	ifaces := strings.Split(string(ifaceOut), "\n")
	for _, iface := range ifaces {
		if strings.TrimSpace(iface) == "" || strings.Contains(iface, "(*)") {
			// This is a garbage line with info or a disabled interface
			continue
		}
		status, err := exec.Command("networksetup", "-getinfo", iface).Output()
		if err != nil {
			return "", err
		}
		if strings.Contains(string(status), gateway.Addr.String()) {
			return iface, nil
		}
	}
	return "", nil
}

func openResolvConf() (*os.File, error) {
	fname := os.Getenv("RESOLV_CONF")
	if fname == "" {
		fname = "/etc/resolv.conf"
	}
	f, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	return f, nil
}
