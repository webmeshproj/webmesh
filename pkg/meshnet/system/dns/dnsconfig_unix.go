//go:build !windows && !wasm && !darwin

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
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	isManagedResolvConf = false
	resolvConf          = "/etc/resolv.conf"
	resolvConfHead      = "/etc/resolv.conf.head"
)

func init() {
	if os.Getenv("RESOLV_CONF") != "" {
		resolvConf = os.Getenv("RESOLV_CONF")
	}
	data, err := os.ReadFile(resolvConf)
	if err != nil {
		return
	}
	if strings.Contains(strings.ToLower(string(data)), "generated") {
		isManagedResolvConf = true
	}
}

func addServers(iface string, servers []netip.AddrPort) error {
	if isManagedResolvConf {
		return appendServersToFile(resolvConfHead, servers)
	}
	return appendServersToFile(resolvConf, servers)
}

func removeServers(iface string, servers []netip.AddrPort) error {
	if isManagedResolvConf {
		return removeServersFromFile(resolvConfHead, servers)
	}
	return removeServersFromFile(resolvConf, servers)
}

func addSearchDomains(iface string, domains []string) error {
	if isManagedResolvConf {
		return appendSearchDomainsToFile(resolvConfHead, domains)
	}
	return appendSearchDomainsToFile(resolvConf, domains)
}

func removeSearchDomains(iface string, domains []string) error {
	if isManagedResolvConf {
		return removeSearchDomainsFromFile(resolvConfHead, domains)
	}
	return removeSearchDomainsFromFile(resolvConf, domains)
}

func appendServersToFile(fname string, servers []netip.AddrPort) error {
	current, err := os.ReadFile(fname)
	if err != nil {
		return err
	}
	f, err := os.Create(fname)
	if err != nil {
		return err
	}
	serverAddrs := toServerAddrs(servers)
	for _, server := range serverAddrs {
		_, err = f.WriteString("nameserver " + server + "\n")
		if err != nil {
			return err
		}
	}
	// Iterate the rest of the file and write it if it doesn't include the
	// added servers
	scanner := bufio.NewScanner(strings.NewReader(string(current)))
Lines:
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if len(line) > 0 && (line[0] == ';' || line[0] == '#') {
			// comment.
			_, err = f.WriteString(line + "\n")
			if err != nil {
				return err
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			if len(fields) > 1 {
				for _, server := range serverAddrs {
					if server == fields[1] {
						continue Lines
					}
				}
			}
			_, err = f.WriteString(line + "\n")
			if err != nil {
				return err
			}
		default:
			_, err = f.WriteString(line + "\n")
			if err != nil {
				return err
			}
		}
	}
	return f.Close()
}

func appendSearchDomainsToFile(fname string, domains []string) error {
	current, err := os.ReadFile(fname)
	if err != nil {
		return err
	}
	f, err := os.Create(fname)
	if err != nil {
		return err
	}
	for _, dom := range domains {
		_, err = f.WriteString("search " + dom + "\n")
		if err != nil {
			return err
		}
	}
	// Iterate the rest of the file and write it if it doesn't include the
	// added servers
	scanner := bufio.NewScanner(strings.NewReader(string(current)))
Lines:
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if len(line) > 0 && (line[0] == ';' || line[0] == '#') {
			// comment.
			_, err = f.WriteString(line + "\n")
			if err != nil {
				return err
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		switch fields[0] {
		case "search":
			if len(fields) > 1 {
				for _, dom := range domains {
					if dom == fields[1] {
						continue Lines
					}
				}
			}
			_, err = f.WriteString(line + "\n")
			if err != nil {
				return err
			}
		default:
			_, err = f.WriteString(line + "\n")
			if err != nil {
				return err
			}
		}
	}
	return f.Close()
}

func removeServersFromFile(fname string, servers []netip.AddrPort) error {
	current, err := os.ReadFile(fname)
	if err != nil {
		return err
	}
	f, err := os.Create(fname)
	if err != nil {
		return err
	}
	serverAddrs := toServerAddrs(servers)
	scanner := bufio.NewScanner(strings.NewReader(string(current)))
Lines:
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if len(line) > 0 && (line[0] == ';' || line[0] == '#') {
			// comment.
			_, err = f.WriteString(line + "\n")
			if err != nil {
				return err
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			if len(fields) > 1 {
				for _, srv := range serverAddrs {
					if srv == fields[1] {
						continue Lines
					}
				}
				_, err = f.WriteString(line + "\n")
				if err != nil {
					return err
				}
			}
		default:
			_, err = f.WriteString(line + "\n")
			if err != nil {
				return err
			}
		}
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return err
	}
	return nil
}

func removeSearchDomainsFromFile(fname string, domains []string) error {
	current, err := os.ReadFile(fname)
	if err != nil {
		return err
	}
	f, err := os.Create(fname)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(current)))
Lines:
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if len(line) > 0 && (line[0] == ';' || line[0] == '#') {
			// comment.
			_, err = f.WriteString(line + "\n")
			if err != nil {
				return err
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		switch fields[0] {
		case "search":
			if len(fields) > 1 {
				for _, dom := range domains {
					if dom == fields[1] {
						continue Lines
					}
				}
				_, err = f.WriteString(line + "\n")
				if err != nil {
					return err
				}
			}
		default:
			_, err = f.WriteString(line + "\n")
			if err != nil {
				return err
			}
		}
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return err
	}
	return nil
}

func toServerAddrs(addrs []netip.AddrPort) []string {
	var serverAddrs []string
	for _, server := range addrs {
		if server.Port() == 53 {
			serverAddrs = append(serverAddrs, server.Addr().String())
		} else {
			// We need to always format as [host]:port
			serverStr := fmt.Sprintf("[%s]:%d", server.Addr().String(), server.Port())
			serverAddrs = append(serverAddrs, serverStr)
		}
	}
	return serverAddrs
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
