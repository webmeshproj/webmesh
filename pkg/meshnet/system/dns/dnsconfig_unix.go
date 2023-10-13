//go:build !windows && !wasm

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

func addServers(_ string, servers []netip.AddrPort) error {
	current, err := readResolvConfHead()
	if err != nil {
		return err
	}
	f, err := os.Create("/etc/resolv.conf.head")
	if err != nil {
		return err
	}
	defer f.Close()
	// Write the new servers
	for _, server := range servers {
		if server.Port() == 53 {
			_, err = f.WriteString("nameserver " + server.Addr().String() + "\n")
		} else {
			// We need to always format as [host]:port
			serverStr := fmt.Sprintf("[%s]:%d", server.Addr().String(), server.Port())
			_, err = f.WriteString("nameserver " + serverStr + "\n")
		}
		if err != nil {
			return err
		}
	}
	// Write the rest of the file
	_, err = f.Write(current)
	if err != nil {
		return err
	}
	return nil
}

func addSearchDomains(_ string, domains []string) error {
	current, err := readResolvConfHead()
	if err != nil {
		return err
	}
	f, err := os.Create("/etc/resolv.conf.head")
	if err != nil {
		return err
	}
	defer f.Close()
	// Write the original file to the head
	_, err = f.Write(current)
	if err != nil {
		return err
	}
	// Write the new search domains
	for _, domain := range domains {
		_, err = f.WriteString("search " + domain + "\n")
		if err != nil {
			return err
		}
	}
	// Allow one ndots (this should be configurable)
	_, err = f.WriteString("options ndots:1\n")
	if err != nil {
		return err
	}
	return nil
}

func removeServers(_ string, servers []netip.AddrPort) error {
	// Create a new resolvconf file, removing the servers
	// if encountered
	current, err := readResolvConfHead()
	if err != nil {
		return err
	}
	f, err := os.Create("/etc/resolv.conf.head")
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(strings.NewReader(string(current)))

Lines:
	for scanner.Scan() {
		line := scanner.Text()
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
				for _, server := range servers {
					if addrport == server {
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

func removeSearchDomains(_ string, domains []string) error {
	// Create a new resolvconf file, removing the domains
	// if encountered
	current, err := readResolvConfHead()
	if err != nil {
		return err
	}
	f, err := os.Create("/etc/resolv.conf.head")
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(strings.NewReader(string(current)))

Lines:
	for scanner.Scan() {
		line := scanner.Text()
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
				for _, domain := range domains {
					for _, field := range fields[1:] {
						if domain == field {
							continue Lines
						}
					}
				}
				_, err = f.WriteString(line + "\n")
				if err != nil {
					return err
				}
			}
		case "options":
			// Remove ndots
			var newOptions []string
			for _, opt := range fields[1:] {
				if !strings.HasPrefix(opt, "ndots:") {
					newOptions = append(newOptions, opt)
				}
			}
			if len(newOptions) > 0 {
				_, err = f.WriteString("options " + strings.Join(newOptions, " ") + "\n")
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

func readResolvConfHead() ([]byte, error) {
	f, err := os.Open("/etc/resolv.conf.head")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}
